/**
 * MijAuth - Browser Storage Extension
 * Session/Local Storage support for .mijauth files
 * 
 * @version 0.3.0
 * @requires MijAuth.js
 */

class MijAuthStorage {
    static VERSION = '0.3.0';
    static STORAGE_KEY = 'mijauth_file';
    static METADATA_KEY = 'mijauth_metadata';

    /**
     * Check if browser supports required features
     * @returns {Object} Support status
     */
    static checkSupport() {
        return {
            localStorage: typeof localStorage !== 'undefined',
            sessionStorage: typeof sessionStorage !== 'undefined',
            indexedDB: typeof indexedDB !== 'undefined',
            isSecure: window.isSecureContext || location.protocol === 'https:',
            crypto: typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined'
        };
    }

    /**
     * Save auth file to browser storage
     * @param {string} fileContent - Base64 encoded .mijauth file content
     * @param {Object} options - Storage options
     * @returns {Promise<Object>} Save result
     */
    static async saveAuthFile(fileContent, options = {}) {
        const {
            storageType = 'session', // 'session', 'local', or 'indexed'
            encrypt = true,
            userId = null,
            expiresIn = null // milliseconds
        } = options;

        const support = this.checkSupport();

        // Security check - only allow on HTTPS
        if (!support.isSecure && storageType !== 'session') {
            throw new Error('Secure context (HTTPS) required for persistent storage');
        }

        const metadata = {
            userId,
            savedAt: new Date().toISOString(),
            expiresAt: expiresIn ? new Date(Date.now() + expiresIn).toISOString() : null,
            version: this.VERSION,
            encrypted: encrypt
        };

        let dataToStore = fileContent;

        // Optional encryption layer for extra security
        if (encrypt && support.crypto) {
            dataToStore = await this._encryptData(fileContent);
            metadata.iv = dataToStore.iv;
        }

        try {
            switch (storageType) {
                case 'session':
                    if (!support.sessionStorage) {
                        throw new Error('SessionStorage not supported');
                    }
                    sessionStorage.setItem(this.STORAGE_KEY, encrypt ? dataToStore.encrypted : dataToStore);
                    sessionStorage.setItem(this.METADATA_KEY, JSON.stringify(metadata));
                    break;

                case 'local':
                    if (!support.localStorage) {
                        throw new Error('LocalStorage not supported');
                    }
                    localStorage.setItem(this.STORAGE_KEY, encrypt ? dataToStore.encrypted : dataToStore);
                    localStorage.setItem(this.METADATA_KEY, JSON.stringify(metadata));
                    break;

                case 'indexed':
                    if (!support.indexedDB) {
                        throw new Error('IndexedDB not supported');
                    }
                    await this._saveToIndexedDB(encrypt ? dataToStore.encrypted : dataToStore, metadata);
                    break;

                default:
                    throw new Error(`Unknown storage type: ${storageType}`);
            }

            return {
                success: true,
                storageType,
                encrypted: encrypt,
                expiresAt: metadata.expiresAt
            };
        } catch (error) {
            throw new Error(`Failed to save auth file: ${error.message}`);
        }
    }

    /**
     * Load auth file from browser storage
     * @param {Object} options - Load options
     * @returns {Promise<string|null>} File content or null if not found/expired
     */
    static async loadAuthFile(options = {}) {
        const {
            storageType = 'session',
            decrypt = true
        } = options;

        try {
            let fileContent = null;
            let metadata = null;

            switch (storageType) {
                case 'session':
                    fileContent = sessionStorage.getItem(this.STORAGE_KEY);
                    metadata = JSON.parse(sessionStorage.getItem(this.METADATA_KEY) || 'null');
                    break;

                case 'local':
                    fileContent = localStorage.getItem(this.STORAGE_KEY);
                    metadata = JSON.parse(localStorage.getItem(this.METADATA_KEY) || 'null');
                    break;

                case 'indexed':
                    const dbData = await this._loadFromIndexedDB();
                    fileContent = dbData?.fileContent;
                    metadata = dbData?.metadata;
                    break;
            }

            if (!fileContent || !metadata) {
                return null;
            }

            // Check expiration
            if (metadata.expiresAt) {
                const expiresAt = new Date(metadata.expiresAt);
                if (expiresAt < new Date()) {
                    await this.clearAuthFile({ storageType });
                    return null;
                }
            }

            // Decrypt if needed
            if (decrypt && metadata.encrypted) {
                const support = this.checkSupport();
                if (!support.crypto) {
                    throw new Error('Crypto API not available for decryption');
                }
                return await this._decryptData(fileContent, metadata.iv);
            }

            return fileContent;
        } catch (error) {
            console.error('Failed to load auth file:', error);
            return null;
        }
    }

    /**
     * Clear auth file from storage
     * @param {Object} options - Clear options
     * @returns {Promise<boolean>} Success status
     */
    static async clearAuthFile(options = {}) {
        const { storageType = 'session' } = options;

        try {
            switch (storageType) {
                case 'session':
                    sessionStorage.removeItem(this.STORAGE_KEY);
                    sessionStorage.removeItem(this.METADATA_KEY);
                    break;

                case 'local':
                    localStorage.removeItem(this.STORAGE_KEY);
                    localStorage.removeItem(this.METADATA_KEY);
                    break;

                case 'indexed':
                    await this._clearIndexedDB();
                    break;
            }
            return true;
        } catch (error) {
            console.error('Failed to clear auth file:', error);
            return false;
        }
    }

    /**
     * Get storage metadata
     * @param {Object} options - Options
     * @returns {Promise<Object|null>} Metadata or null
     */
    static async getMetadata(options = {}) {
        const { storageType = 'session' } = options;

        try {
            let metadata = null;

            switch (storageType) {
                case 'session':
                    metadata = JSON.parse(sessionStorage.getItem(this.METADATA_KEY) || 'null');
                    break;

                case 'local':
                    metadata = JSON.parse(localStorage.getItem(this.METADATA_KEY) || 'null');
                    break;

                case 'indexed':
                    const dbData = await this._loadFromIndexedDB();
                    metadata = dbData?.metadata;
                    break;
            }

            return metadata;
        } catch (error) {
            console.error('Failed to get metadata:', error);
            return null;
        }
    }

    // ========================================
    // Private Methods - Encryption
    // ========================================

    static async _encryptData(data) {
        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(data);

        // Generate encryption key from user's session
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(await this._getSessionKey()),
            { name: 'PBKDF2' },
            false,
            ['deriveBits', 'deriveKey']
        );

        const key = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: encoder.encode('mijauth-v0.3.0'),
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt']
        );

        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encryptedBuffer = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key,
            dataBuffer
        );

        return {
            encrypted: this._arrayBufferToBase64(encryptedBuffer),
            iv: this._arrayBufferToBase64(iv)
        };
    }

    static async _decryptData(encryptedData, ivBase64) {
        const encoder = new TextEncoder();
        const decoder = new TextDecoder();

        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(await this._getSessionKey()),
            { name: 'PBKDF2' },
            false,
            ['deriveBits', 'deriveKey']
        );

        const key = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: encoder.encode('mijauth-v0.3.0'),
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']
        );

        const iv = this._base64ToArrayBuffer(ivBase64);
        const encryptedBuffer = this._base64ToArrayBuffer(encryptedData);

        const decryptedBuffer = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            key,
            encryptedBuffer
        );

        return decoder.decode(decryptedBuffer);
    }

    static async _getSessionKey() {
        // Generate or retrieve session-based key
        let sessionKey = sessionStorage.getItem('mijauth_session_key');
        if (!sessionKey) {
            sessionKey = this._generateRandomString(32);
            sessionStorage.setItem('mijauth_session_key', sessionKey);
        }
        return sessionKey;
    }

    // ========================================
    // Private Methods - IndexedDB
    // ========================================

    static _openDB() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open('MijAuthDB', 1);

            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(request.result);

            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                if (!db.objectStoreNames.contains('authFiles')) {
                    db.createObjectStore('authFiles', { keyPath: 'id' });
                }
            };
        });
    }

    static async _saveToIndexedDB(fileContent, metadata) {
        const db = await this._openDB();
        const transaction = db.transaction(['authFiles'], 'readwrite');
        const store = transaction.objectStore('authFiles');

        return new Promise((resolve, reject) => {
            const request = store.put({
                id: 'current',
                fileContent,
                metadata
            });

            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }

    static async _loadFromIndexedDB() {
        const db = await this._openDB();
        const transaction = db.transaction(['authFiles'], 'readonly');
        const store = transaction.objectStore('authFiles');

        return new Promise((resolve, reject) => {
            const request = store.get('current');

            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    static async _clearIndexedDB() {
        const db = await this._openDB();
        const transaction = db.transaction(['authFiles'], 'readwrite');
        const store = transaction.objectStore('authFiles');

        return new Promise((resolve, reject) => {
            const request = store.delete('current');

            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }

    // ========================================
    // Utility Methods
    // ========================================

    static _arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    static _base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    static _generateRandomString(length) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        const randomValues = new Uint8Array(length);
        crypto.getRandomValues(randomValues);
        return Array.from(randomValues)
            .map(x => chars[x % chars.length])
            .join('');
    }
}

// Export for Node.js/CommonJS
if (typeof module !== 'undefined' && module.exports) {
    module.exports = MijAuthStorage;
}
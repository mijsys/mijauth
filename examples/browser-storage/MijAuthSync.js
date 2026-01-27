/**
 * MijAuth - Multi-device Sync Helper
 * End-to-end encrypted payload helper (transport provided by app)
 *
 * @version 0.3.0
 */
class MijAuthSync {
    static VERSION = '0.3.0';

    static async encryptForSync(fileContent, syncKey, options = {}) {
        const { salt = 'mijauth-sync-v0.3.0', iterations = 150000 } = options;
        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(fileContent);

        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(syncKey),
            { name: 'PBKDF2' },
            false,
            ['deriveBits', 'deriveKey']
        );

        const key = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: encoder.encode(salt),
                iterations,
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
            payload: this._arrayBufferToBase64(encryptedBuffer),
            iv: this._arrayBufferToBase64(iv),
            createdAt: new Date().toISOString(),
            version: this.VERSION,
            iterations,
            salt
        };
    }

    static async decryptFromSync(syncPayload, syncKey) {
        const encoder = new TextEncoder();
        const decoder = new TextDecoder();

        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(syncKey),
            { name: 'PBKDF2' },
            false,
            ['deriveBits', 'deriveKey']
        );

        const key = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: encoder.encode(syncPayload.salt || 'mijauth-sync-v0.3.0'),
                iterations: syncPayload.iterations || 150000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']
        );

        const iv = this._base64ToArrayBuffer(syncPayload.iv);
        const encryptedBuffer = this._base64ToArrayBuffer(syncPayload.payload);

        const decryptedBuffer = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            key,
            encryptedBuffer
        );

        return decoder.decode(decryptedBuffer);
    }

    static async pushToTransport(syncPayload, transport) {
        if (!transport || typeof transport.push !== 'function') {
            throw new Error('Invalid transport: missing push()');
        }
        return transport.push(syncPayload);
    }

    static async pullFromTransport(transport) {
        if (!transport || typeof transport.pull !== 'function') {
            throw new Error('Invalid transport: missing pull()');
        }
        return transport.pull();
    }

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
}

class MijAuthMemoryTransport {
    constructor() {
        this.payload = null;
    }

    async push(payload) {
        this.payload = payload;
        return { success: true };
    }

    async pull() {
        return this.payload;
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { MijAuthSync, MijAuthMemoryTransport };
}

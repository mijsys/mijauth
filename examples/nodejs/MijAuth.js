/**
 * MijAuth - System Weryfikacji Dwuetapowej (2FA) oparty na plikach
 * Implementacja Node.js (JavaScript/TypeScript)
 * 
 * Wymaga Node.js 16+ (używa wbudowanego modułu crypto)
 */

const crypto = require('crypto');
const fs = require('fs');

class MijAuth {
    static ALGORITHM = 'aes-256-gcm';
    static KEY_LENGTH = 32; // 256 bits
    static IV_LENGTH = 12;  // 96 bits dla GCM
    static TAG_LENGTH = 16; // 128 bits
    static VERSION = 1;

    /**
     * Generuje nowy klucz AES-256 dla użytkownika
     * @returns {string} Klucz w formacie base64
     */
    static generateUserKey() {
        const key = crypto.randomBytes(this.KEY_LENGTH);
        return key.toString('base64');
    }

    /**
     * Generuje unikalny token dla użytkownika
     * @returns {string} Token w formacie hex
     */
    static generateToken() {
        return crypto.randomBytes(32).toString('hex');
    }

    /**
     * Tworzy zaszyfrowany plik autoryzacyjny .mijauth
     * 
     * @param {string} userId - Identyfikator użytkownika
     * @param {string} userKeyBase64 - Klucz użytkownika w base64
     * @param {string|null} deviceHash - Opcjonalny hash urządzenia
     * @returns {{fileContent: string, token: string}}
     */
    static createAuthFile(userId, userKeyBase64, deviceHash = null, deviceHashV2 = null) {
        const token = this.generateToken();
        
        const payload = {
            user_id: userId,
            token: token,
            created_at: new Date().toISOString(),
            device_hash: deviceHash,
            device_hash_v2: deviceHashV2,
            version: this.VERSION
        };

        const jsonPayload = JSON.stringify(payload);
        const encryptedContent = this.encrypt(jsonPayload, userKeyBase64);

        return {
            fileContent: encryptedContent,
            token: token
        };
    }

    /**
     * Weryfikuje plik autoryzacyjny i zwraca dane użytkownika
     * 
     * @param {string} fileContent - Zawartość pliku .mijauth
     * @param {string} userKeyBase64 - Klucz użytkownika w base64
     * @returns {object|null} Dane użytkownika lub null
     */
    static verifyAuthFile(fileContent, userKeyBase64) {
        try {
            const decrypted = this.decrypt(fileContent, userKeyBase64);
            
            if (decrypted === null) {
                return null;
            }

            const payload = JSON.parse(decrypted);
            
            // Walidacja struktury
            if (!payload.user_id || !payload.token || !payload.version) {
                return null;
            }

            return payload;
        } catch (e) {
            return null;
        }
    }

    /**
     * Weryfikuje plik i sprawdza czy token zgadza się z przechowywanym
     * 
     * @param {string} fileContent - Zawartość pliku .mijauth
     * @param {string} userKeyBase64 - Klucz użytkownika w base64
     * @param {string} expectedToken - Oczekiwany token z bazy danych
     * @param {string} expectedUserId - Oczekiwane ID użytkownika
     * @returns {boolean}
     */
    static verifyAuthFileWithToken(fileContent, userKeyBase64, expectedToken, expectedUserId) {
        const payload = this.verifyAuthFile(fileContent, userKeyBase64);
        
        if (payload === null) {
            return false;
        }

        // Constant-time comparison
        const tokenMatch = crypto.timingSafeEqual(
            Buffer.from(expectedToken),
            Buffer.from(payload.token)
        );
        const userIdMatch = crypto.timingSafeEqual(
            Buffer.from(expectedUserId),
            Buffer.from(payload.user_id)
        );

        return tokenMatch && userIdMatch;
    }

    /**
     * Weryfikuje plik, token i hash urządzenia (v1/v2)
     *
     * @param {string} fileContent
     * @param {string} userKeyBase64
     * @param {string} expectedToken
     * @param {string} expectedUserId
     * @param {string|null} expectedDeviceHash
     * @param {string|null} expectedDeviceHashV2
     * @returns {boolean}
     */
    static verifyAuthFileWithTokenAndDevice(
        fileContent,
        userKeyBase64,
        expectedToken,
        expectedUserId,
        expectedDeviceHash = null,
        expectedDeviceHashV2 = null
    ) {
        const payload = this.verifyAuthFile(fileContent, userKeyBase64);

        if (payload === null) {
            return false;
        }

        const tokenMatch = crypto.timingSafeEqual(
            Buffer.from(expectedToken),
            Buffer.from(payload.token)
        );
        const userIdMatch = crypto.timingSafeEqual(
            Buffer.from(expectedUserId),
            Buffer.from(payload.user_id)
        );

        if (!tokenMatch || !userIdMatch) {
            return false;
        }

        if (expectedDeviceHash !== null) {
            if (!payload.device_hash) {
                return false;
            }
            const deviceMatch = crypto.timingSafeEqual(
                Buffer.from(expectedDeviceHash),
                Buffer.from(payload.device_hash)
            );
            if (!deviceMatch) {
                return false;
            }
        }

        if (expectedDeviceHashV2 !== null) {
            if (!payload.device_hash_v2) {
                return false;
            }
            const deviceMatchV2 = crypto.timingSafeEqual(
                Buffer.from(expectedDeviceHashV2),
                Buffer.from(payload.device_hash_v2)
            );
            if (!deviceMatchV2) {
                return false;
            }
        }

        return true;
    }

    /**
     * Regeneruje plik autoryzacyjny (nowy token)
     * 
     * @param {string} userId - Identyfikator użytkownika
     * @param {string} userKeyBase64 - Klucz użytkownika w base64
     * @param {string|null} deviceHash - Opcjonalny hash urządzenia
     * @returns {{fileContent: string, token: string}}
     */
    static regenerateAuthFile(userId, userKeyBase64, deviceHash = null, deviceHashV2 = null) {
        return this.createAuthFile(userId, userKeyBase64, deviceHash, deviceHashV2);
    }

    /**
     * Szyfruje dane przy użyciu AES-256-GCM
     * 
     * @param {string} plaintext - Dane do zaszyfrowania
     * @param {string} keyBase64 - Klucz w formacie base64
     * @returns {string} Zaszyfrowane dane w formacie base64
     */
    static encrypt(plaintext, keyBase64) {
        const key = Buffer.from(keyBase64, 'base64');
        const iv = crypto.randomBytes(this.IV_LENGTH);

        const cipher = crypto.createCipheriv(this.ALGORITHM, key, iv);
        
        let ciphertext = cipher.update(plaintext, 'utf8');
        ciphertext = Buffer.concat([ciphertext, cipher.final()]);
        
        const tag = cipher.getAuthTag();

        // Format: IV (12 bytes) + Tag (16 bytes) + Ciphertext
        const combined = Buffer.concat([iv, tag, ciphertext]);
        
        return combined.toString('base64');
    }

    /**
     * Odszyfrowuje dane przy użyciu AES-256-GCM
     * 
     * @param {string} encryptedBase64 - Zaszyfrowane dane w formacie base64
     * @param {string} keyBase64 - Klucz w formacie base64
     * @returns {string|null} Odszyfrowane dane lub null przy błędzie
     */
    static decrypt(encryptedBase64, keyBase64) {
        try {
            const key = Buffer.from(keyBase64, 'base64');
            const combined = Buffer.from(encryptedBase64, 'base64');

            if (combined.length < this.IV_LENGTH + this.TAG_LENGTH) {
                return null;
            }

            const iv = combined.subarray(0, this.IV_LENGTH);
            const tag = combined.subarray(this.IV_LENGTH, this.IV_LENGTH + this.TAG_LENGTH);
            const ciphertext = combined.subarray(this.IV_LENGTH + this.TAG_LENGTH);

            const decipher = crypto.createDecipheriv(this.ALGORITHM, key, iv);
            decipher.setAuthTag(tag);

            let plaintext = decipher.update(ciphertext);
            plaintext = Buffer.concat([plaintext, decipher.final()]);

            return plaintext.toString('utf8');
        } catch (e) {
            return null;
        }
    }

    /**
     * Generuje hash urządzenia na podstawie headers (dla Express.js)
     * 
     * @param {object} headers - Obiekt nagłówków HTTP
     * @returns {string} Hash urządzenia
     */
    static generateDeviceHash(headers) {
        const data = {
            user_agent: headers['user-agent'] || '',
            accept_language: headers['accept-language'] || ''
        };

        return crypto.createHash('sha256')
            .update(JSON.stringify(data))
            .digest('hex');
    }

    /**
     * Generuje hash urządzenia v2 z rozszerzonego kontekstu
     *
     * @param {object} context
     * @returns {string}
     */
    static generateDeviceHashV2(context = {}) {
        const normalized = this._normalizeFingerprintContext(context);
        return crypto.createHash('sha256')
            .update(JSON.stringify(normalized))
            .digest('hex');
    }

    static _normalizeFingerprintContext(context) {
        const normalized = {};
        Object.keys(context)
            .sort()
            .forEach((key) => {
                const value = context[key];
                if (value === null || value === undefined) {
                    return;
                }
                if (typeof value === 'object' && !Array.isArray(value)) {
                    normalized[key] = this._normalizeFingerprintContext(value);
                } else {
                    normalized[key] = value;
                }
            });
        return normalized;
    }
}

/**
 * Symulacja bazy danych użytkowników
 */
class UserDatabase {
    constructor(storageFile = 'users.json') {
        this.storageFile = storageFile;
        this.users = {};
        this.load();
    }

    load() {
        try {
            if (fs.existsSync(this.storageFile)) {
                const data = fs.readFileSync(this.storageFile, 'utf8');
                this.users = JSON.parse(data);
            }
        } catch (e) {
            this.users = {};
        }
    }

    save() {
        fs.writeFileSync(this.storageFile, JSON.stringify(this.users, null, 2));
    }

    async createUser(userId, email, password) {
        const userKey = MijAuth.generateUserKey();
        const authResult = MijAuth.createAuthFile(userId, userKey);

        // Hashowanie hasła (prosty przykład - w produkcji użyj bcrypt/argon2)
        const passwordHash = crypto.createHash('sha256')
            .update(password + 'salt_' + userId)
            .digest('hex');

        this.users[userId] = {
            id: userId,
            email: email,
            password_hash: passwordHash,
            encryption_key: userKey,
            auth_token: authResult.token,
            created_at: new Date().toISOString()
        };

        this.save();

        return {
            user: this.users[userId],
            authFile: authResult.fileContent
        };
    }

    getUser(userId) {
        return this.users[userId] || null;
    }

    getUserByEmail(email) {
        return Object.values(this.users).find(u => u.email === email) || null;
    }

    verifyPassword(user, password) {
        const hash = crypto.createHash('sha256')
            .update(password + 'salt_' + user.id)
            .digest('hex');
        return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(user.password_hash));
    }

    updateAuthToken(userId, newToken) {
        if (this.users[userId]) {
            this.users[userId].auth_token = newToken;
            this.save();
        }
    }
}

module.exports = { MijAuth, UserDatabase };

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
    static DEFAULT_AUTH_FILE_TTL_SECONDS = 30 * 24 * 60 * 60;

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
    static verifyAuthFile(fileContent, userKeyBase64, maxAgeSeconds = this.DEFAULT_AUTH_FILE_TTL_SECONDS) {
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

            if (!this.isAuthFileWithinTtl(payload, maxAgeSeconds)) {
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
    static verifyAuthFileWithToken(
        fileContent,
        userKeyBase64,
        expectedToken,
        expectedUserId,
        maxAgeSeconds = this.DEFAULT_AUTH_FILE_TTL_SECONDS
    ) {
        const payload = this.verifyAuthFile(fileContent, userKeyBase64, maxAgeSeconds);
        
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
            accept_language: headers['accept-language'] || '',
            device_id: headers['x-mijauth-device-id'] || ''
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

    static generateTotpSecret(length = 32) {
        if (length < 16) {
            throw new Error('TOTP secret must have at least 16 Base32 chars');
        }
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        const bytes = crypto.randomBytes(length);
        let secret = '';
        for (let i = 0; i < length; i++) {
            secret += alphabet[bytes[i] % 32];
        }
        return secret;
    }

    static getTotpProvisioningUri(accountName, issuer, secret, digits = 6, period = 30) {
        const label = encodeURIComponent(`${issuer}:${accountName}`);
        const query = new URLSearchParams({
            secret: secret.toUpperCase(),
            issuer,
            algorithm: 'SHA1',
            digits: String(digits),
            period: String(period)
        }).toString();
        return `otpauth://totp/${label}?${query}`;
    }

    static generateTotpCode(secret, timestamp = Date.now(), period = 30, digits = 6) {
        const counter = Math.floor(timestamp / 1000 / period);
        return this.generateHotpCode(secret, counter, digits);
    }

    static verifyTotp(secret, code, discrepancy = 1, timestamp = Date.now(), period = 30, digits = 6) {
        const normalizedCode = String(code).replace(/\s+/g, '');
        if (!new RegExp(`^\\d{${digits}}$`).test(normalizedCode)) {
            return false;
        }

        const counter = Math.floor(timestamp / 1000 / period);
        for (let offset = -discrepancy; offset <= discrepancy; offset++) {
            const candidate = this.generateHotpCode(secret, counter + offset, digits);
            if (crypto.timingSafeEqual(Buffer.from(candidate), Buffer.from(normalizedCode))) {
                return true;
            }
        }
        return false;
    }

    static generateHotpCode(secret, counter, digits = 6) {
        if (counter < 0) {
            return '0'.repeat(digits);
        }
        const secretBuffer = this.base32Decode(secret);
        if (!secretBuffer || secretBuffer.length === 0) {
            throw new Error('Invalid TOTP secret');
        }

        const counterBuffer = Buffer.alloc(8);
        counterBuffer.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
        counterBuffer.writeUInt32BE(counter >>> 0, 4);

        const hash = crypto.createHmac('sha1', secretBuffer).update(counterBuffer).digest();
        const offset = hash[hash.length - 1] & 0x0f;
        const binary =
            ((hash[offset] & 0x7f) << 24) |
            ((hash[offset + 1] & 0xff) << 16) |
            ((hash[offset + 2] & 0xff) << 8) |
            (hash[offset + 3] & 0xff);

        return String(binary % (10 ** digits)).padStart(digits, '0');
    }

    static base32Decode(secret) {
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        const map = new Map(alphabet.split('').map((char, idx) => [char, idx]));
        const normalized = String(secret).toUpperCase().replace(/=|\s+/g, '');
        let bits = '';

        for (const char of normalized) {
            if (!map.has(char)) {
                return Buffer.alloc(0);
            }
            bits += map.get(char).toString(2).padStart(5, '0');
        }

        const bytes = [];
        for (let i = 0; i + 8 <= bits.length; i += 8) {
            bytes.push(parseInt(bits.slice(i, i + 8), 2));
        }

        return Buffer.from(bytes);
    }

    static isAuthFileWithinTtl(payload, maxAgeSeconds) {
        if (maxAgeSeconds === null || maxAgeSeconds === undefined) {
            return true;
        }

        const createdAt = Date.parse(payload.created_at || '');
        if (Number.isNaN(createdAt)) {
            return false;
        }

        const now = Date.now();
        if (createdAt > now) {
            return false;
        }

        return (now - createdAt) <= maxAgeSeconds * 1000;
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
        const totpSecret = MijAuth.generateTotpSecret();

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
            totp_secret: totpSecret,
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

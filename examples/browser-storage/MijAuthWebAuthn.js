/**
 * MijAuth - WebAuthn Helper
 * Minimal client-side helper for registration and authentication
 *
 * @version 0.3.0
 */
class MijAuthWebAuthn {
    static VERSION = '0.3.0';

    static isSupported() {
        return typeof window !== 'undefined'
            && !!window.PublicKeyCredential
            && typeof navigator !== 'undefined'
            && !!navigator.credentials;
    }

    static async register({
        challenge,
        userId,
        userName,
        userDisplayName,
        rpId,
        rpName,
        timeout = 60000,
        attestation = 'none'
    }) {
        if (!this.isSupported()) {
            throw new Error('WebAuthn not supported');
        }

        const publicKey = {
            challenge: this._base64urlToUint8Array(challenge),
            rp: {
                id: rpId || window.location.hostname,
                name: rpName || 'MijAuth'
            },
            user: {
                id: this._base64urlToUint8Array(userId),
                name: userName,
                displayName: userDisplayName || userName
            },
            pubKeyCredParams: [
                { type: 'public-key', alg: -7 },  // ES256
                { type: 'public-key', alg: -257 } // RS256
            ],
            timeout,
            attestation
        };

        const credential = await navigator.credentials.create({ publicKey });
        return this._serializeAttestation(credential);
    }

    static async authenticate({
        challenge,
        allowCredentialIds = [],
        rpId,
        timeout = 60000,
        userVerification = 'preferred'
    }) {
        if (!this.isSupported()) {
            throw new Error('WebAuthn not supported');
        }

        const publicKey = {
            challenge: this._base64urlToUint8Array(challenge),
            rpId: rpId || window.location.hostname,
            allowCredentials: allowCredentialIds.map(id => ({
                type: 'public-key',
                id: this._base64urlToUint8Array(id)
            })),
            timeout,
            userVerification
        };

        const assertion = await navigator.credentials.get({ publicKey });
        return this._serializeAssertion(assertion);
    }

    static _serializeAttestation(credential) {
        return {
            id: credential.id,
            rawId: this._uint8ArrayToBase64url(new Uint8Array(credential.rawId)),
            type: credential.type,
            response: {
                clientDataJSON: this._uint8ArrayToBase64url(new Uint8Array(credential.response.clientDataJSON)),
                attestationObject: this._uint8ArrayToBase64url(new Uint8Array(credential.response.attestationObject))
            }
        };
    }

    static _serializeAssertion(assertion) {
        return {
            id: assertion.id,
            rawId: this._uint8ArrayToBase64url(new Uint8Array(assertion.rawId)),
            type: assertion.type,
            response: {
                clientDataJSON: this._uint8ArrayToBase64url(new Uint8Array(assertion.response.clientDataJSON)),
                authenticatorData: this._uint8ArrayToBase64url(new Uint8Array(assertion.response.authenticatorData)),
                signature: this._uint8ArrayToBase64url(new Uint8Array(assertion.response.signature)),
                userHandle: assertion.response.userHandle
                    ? this._uint8ArrayToBase64url(new Uint8Array(assertion.response.userHandle))
                    : null
            }
        };
    }

    static _base64urlToUint8Array(base64url) {
        const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        const padLength = (4 - (base64.length % 4)) % 4;
        const padded = base64 + '='.repeat(padLength);
        const binary = atob(padded);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

    static _uint8ArrayToBase64url(bytes) {
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        const base64 = btoa(binary);
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = MijAuthWebAuthn;
}

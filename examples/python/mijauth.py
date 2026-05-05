"""
MijAuth - System Weryfikacji Dwuetapowej (2FA) oparty na plikach
Implementacja Python

Wymaga: pip install cryptography
"""

import os
import json
import hashlib
import secrets
import hmac
import base64
import struct
from datetime import datetime
from base64 import b64encode, b64decode
from typing import Optional, Tuple, Dict, Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class MijAuth:
    """Główna klasa systemu MijAuth do weryfikacji dwuetapowej"""
    
    KEY_LENGTH = 32   # 256 bits
    IV_LENGTH = 12    # 96 bits dla GCM
    TAG_LENGTH = 16   # 128 bits (domyślnie w AESGCM)
    VERSION = 1
    DEFAULT_AUTH_FILE_TTL_SECONDS = 30 * 24 * 60 * 60

    @staticmethod
    def generate_user_key() -> str:
        """
        Generuje nowy klucz AES-256 dla użytkownika
        
        Returns:
            Klucz w formacie base64
        """
        key = secrets.token_bytes(MijAuth.KEY_LENGTH)
        return b64encode(key).decode('utf-8')

    @staticmethod
    def generate_token() -> str:
        """
        Generuje unikalny token dla użytkownika
        
        Returns:
            Token w formacie hex
        """
        return secrets.token_hex(32)

    @staticmethod
    def create_auth_file(
        user_id: str,
        user_key_base64: str,
        device_hash: Optional[str] = None,
        device_hash_v2: Optional[str] = None
    ) -> Tuple[str, str]:
        """
        Tworzy zaszyfrowany plik autoryzacyjny .mijauth
        
        Args:
            user_id: Identyfikator użytkownika
            user_key_base64: Klucz użytkownika w base64
            device_hash: Opcjonalny hash urządzenia
            
        Returns:
            Tuple (zawartość pliku, token)
        """
        token = MijAuth.generate_token()
        
        payload = {
            'user_id': user_id,
            'token': token,
            'created_at': datetime.utcnow().isoformat() + 'Z',
            'device_hash': device_hash,
            'device_hash_v2': device_hash_v2,
            'version': MijAuth.VERSION
        }

        json_payload = json.dumps(payload)
        encrypted_content = MijAuth._encrypt(json_payload, user_key_base64)

        return encrypted_content, token

    @staticmethod
    def verify_auth_file(
        file_content: str,
        user_key_base64: str,
        max_age_seconds: Optional[int] = DEFAULT_AUTH_FILE_TTL_SECONDS
    ) -> Optional[Dict[str, Any]]:
        """
        Weryfikuje plik autoryzacyjny i zwraca dane użytkownika
        
        Args:
            file_content: Zawartość pliku .mijauth
            user_key_base64: Klucz użytkownika w base64
            
        Returns:
            Dane użytkownika lub None
        """
        try:
            decrypted = MijAuth._decrypt(file_content, user_key_base64)
            
            if decrypted is None:
                return None

            payload = json.loads(decrypted)
            
            # Walidacja struktury
            if not all(key in payload for key in ['user_id', 'token', 'version']):
                return None

            if not MijAuth._is_auth_file_within_ttl(payload, max_age_seconds):
                return None

            return payload
        except Exception:
            return None

    @staticmethod
    def verify_auth_file_with_token(
        file_content: str,
        user_key_base64: str,
        expected_token: str,
        expected_user_id: str,
        max_age_seconds: Optional[int] = DEFAULT_AUTH_FILE_TTL_SECONDS
    ) -> bool:
        """
        Weryfikuje plik i sprawdza czy token zgadza się z przechowywanym
        
        Args:
            file_content: Zawartość pliku .mijauth
            user_key_base64: Klucz użytkownika w base64
            expected_token: Oczekiwany token z bazy danych
            expected_user_id: Oczekiwane ID użytkownika
            
        Returns:
            True jeśli weryfikacja pomyślna
        """
        payload = MijAuth.verify_auth_file(file_content, user_key_base64, max_age_seconds)
        
        if payload is None:
            return False

        # Constant-time comparison
        token_match = secrets.compare_digest(expected_token, payload['token'])
        user_id_match = secrets.compare_digest(expected_user_id, payload['user_id'])

        return token_match and user_id_match

    @staticmethod
    def verify_auth_file_with_token_and_device(
        file_content: str,
        user_key_base64: str,
        expected_token: str,
        expected_user_id: str,
        expected_device_hash: Optional[str] = None,
        expected_device_hash_v2: Optional[str] = None
    ) -> bool:
        payload = MijAuth.verify_auth_file(file_content, user_key_base64)

        if payload is None:
            return False

        token_match = secrets.compare_digest(expected_token, payload['token'])
        user_id_match = secrets.compare_digest(expected_user_id, payload['user_id'])

        if not token_match or not user_id_match:
            return False

        if expected_device_hash is not None:
            if 'device_hash' not in payload:
                return False
            if not secrets.compare_digest(expected_device_hash, str(payload['device_hash'])):
                return False

        if expected_device_hash_v2 is not None:
            if 'device_hash_v2' not in payload:
                return False
            if not secrets.compare_digest(expected_device_hash_v2, str(payload['device_hash_v2'])):
                return False

        return True

    @staticmethod
    def regenerate_auth_file(
        user_id: str,
        user_key_base64: str,
        device_hash: Optional[str] = None,
        device_hash_v2: Optional[str] = None
    ) -> Tuple[str, str]:
        """
        Regeneruje plik autoryzacyjny (nowy token)
        
        Args:
            user_id: Identyfikator użytkownika
            user_key_base64: Klucz użytkownika w base64
            device_hash: Opcjonalny hash urządzenia
            
        Returns:
            Tuple (zawartość pliku, token)
        """
        return MijAuth.create_auth_file(user_id, user_key_base64, device_hash, device_hash_v2)

    @staticmethod
    def _encrypt(plaintext: str, key_base64: str) -> str:
        """
        Szyfruje dane przy użyciu AES-256-GCM
        
        Args:
            plaintext: Dane do zaszyfrowania
            key_base64: Klucz w formacie base64
            
        Returns:
            Zaszyfrowane dane w formacie base64
        """
        key = b64decode(key_base64)
        iv = secrets.token_bytes(MijAuth.IV_LENGTH)
        
        aesgcm = AESGCM(key)
        ciphertext_with_tag = aesgcm.encrypt(iv, plaintext.encode('utf-8'), None)
        
        # Format: IV (12 bytes) + Ciphertext + Tag (ostatnie 16 bytes w ciphertext_with_tag)
        combined = iv + ciphertext_with_tag
        
        return b64encode(combined).decode('utf-8')

    @staticmethod
    def _decrypt(encrypted_base64: str, key_base64: str) -> Optional[str]:
        """
        Odszyfrowuje dane przy użyciu AES-256-GCM
        
        Args:
            encrypted_base64: Zaszyfrowane dane w formacie base64
            key_base64: Klucz w formacie base64
            
        Returns:
            Odszyfrowane dane lub None przy błędzie
        """
        try:
            key = b64decode(key_base64)
            combined = b64decode(encrypted_base64)

            if len(combined) < MijAuth.IV_LENGTH + MijAuth.TAG_LENGTH:
                return None

            iv = combined[:MijAuth.IV_LENGTH]
            ciphertext_with_tag = combined[MijAuth.IV_LENGTH:]

            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(iv, ciphertext_with_tag, None)

            return plaintext.decode('utf-8')
        except Exception:
            return None

    @staticmethod
    def generate_device_hash(user_agent: str = '', accept_language: str = '') -> str:
        """
        Generuje hash urządzenia na podstawie headers
        
        Args:
            user_agent: User-Agent header
            accept_language: Accept-Language header
            
        Returns:
            Hash urządzenia
        """
        data = json.dumps({
            'user_agent': user_agent,
            'accept_language': accept_language
        })
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    @staticmethod
    def generate_totp_secret(length: int = 32) -> str:
        if length < 16:
            raise ValueError('Sekret TOTP musi mieć co najmniej 16 znaków Base32')

        alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
        random_bytes = secrets.token_bytes(length)
        return ''.join(alphabet[b % 32] for b in random_bytes)

    @staticmethod
    def get_totp_provisioning_uri(
        account_name: str,
        issuer: str,
        secret: str,
        digits: int = 6,
        period: int = 30
    ) -> str:
        import urllib.parse

        label = urllib.parse.quote(f'{issuer}:{account_name}')
        query = urllib.parse.urlencode({
            'secret': secret.upper(),
            'issuer': issuer,
            'algorithm': 'SHA1',
            'digits': digits,
            'period': period
        })
        return f'otpauth://totp/{label}?{query}'

    @staticmethod
    def generate_totp_code(secret: str, timestamp: Optional[int] = None, period: int = 30, digits: int = 6) -> str:
        ts = timestamp or int(datetime.utcnow().timestamp())
        counter = ts // period
        return MijAuth._generate_hotp_code(secret, counter, digits)

    @staticmethod
    def verify_totp(
        secret: str,
        code: str,
        discrepancy: int = 1,
        timestamp: Optional[int] = None,
        period: int = 30,
        digits: int = 6
    ) -> bool:
        normalized_code = ''.join(code.split())

        if not normalized_code.isdigit() or len(normalized_code) != digits:
            return False

        ts = timestamp or int(datetime.utcnow().timestamp())
        counter = ts // period

        for offset in range(-discrepancy, discrepancy + 1):
            candidate = MijAuth._generate_hotp_code(secret, counter + offset, digits)
            if secrets.compare_digest(candidate, normalized_code):
                return True

        return False

    @staticmethod
    def generate_device_hash_v2(context: Optional[Dict[str, Any]] = None) -> str:
        if context is None:
            context = {}

        normalized = MijAuth._normalize_fingerprint_context(context)
        data = json.dumps(normalized, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    @staticmethod
    def _normalize_fingerprint_context(context: Dict[str, Any]) -> Dict[str, Any]:
        normalized: Dict[str, Any] = {}
        for key, value in context.items():
            if value is None:
                continue
            if isinstance(value, dict):
                normalized[key] = MijAuth._normalize_fingerprint_context(value)
            else:
                normalized[key] = value
        return dict(sorted(normalized.items()))

    @staticmethod
    def _generate_hotp_code(secret: str, counter: int, digits: int = 6) -> str:
        if counter < 0:
            return '0' * digits

        secret_bytes = MijAuth._base32_decode(secret)
        if not secret_bytes:
            raise ValueError('Nieprawidłowy sekret TOTP')

        counter_bytes = struct.pack('>Q', counter)
        digest = hmac.new(secret_bytes, counter_bytes, hashlib.sha1).digest()
        offset = digest[-1] & 0x0F

        binary = (
            ((digest[offset] & 0x7F) << 24)
            | ((digest[offset + 1] & 0xFF) << 16)
            | ((digest[offset + 2] & 0xFF) << 8)
            | (digest[offset + 3] & 0xFF)
        )

        otp = binary % (10 ** digits)
        return str(otp).zfill(digits)

    @staticmethod
    def _base32_decode(secret: str) -> bytes:
        normalized = ''.join(secret.split()).upper().replace('=', '')
        padding = '=' * ((8 - len(normalized) % 8) % 8)

        try:
            return base64.b32decode(normalized + padding, casefold=True)
        except Exception:
            return b''

    @staticmethod
    def _is_auth_file_within_ttl(payload: Dict[str, Any], max_age_seconds: Optional[int]) -> bool:
        if max_age_seconds is None:
            return True

        created_at = payload.get('created_at')
        if not isinstance(created_at, str):
            return False

        try:
            ts = datetime.fromisoformat(created_at.replace('Z', '+00:00')).timestamp()
        except ValueError:
            return False

        now = datetime.utcnow().timestamp()
        if ts > now:
            return False

        return (now - ts) <= max_age_seconds


class UserDatabase:
    """Symulacja bazy danych użytkowników"""
    
    def __init__(self, storage_file: str = 'users.json'):
        self.storage_file = storage_file
        self.users: Dict[str, Dict] = {}
        self._load()

    def _load(self) -> None:
        """Ładuje dane z pliku"""
        if os.path.exists(self.storage_file):
            with open(self.storage_file, 'r') as f:
                self.users = json.load(f)

    def _save(self) -> None:
        """Zapisuje dane do pliku"""
        with open(self.storage_file, 'w') as f:
            json.dump(self.users, f, indent=2)

    def create_user(self, user_id: str, email: str, password: str) -> Tuple[Dict, str]:
        """
        Tworzy nowego użytkownika
        
        Args:
            user_id: ID użytkownika
            email: Email użytkownika
            password: Hasło użytkownika
            
        Returns:
            Tuple (dane użytkownika, zawartość pliku auth)
        """
        user_key = MijAuth.generate_user_key()
        file_content, token = MijAuth.create_auth_file(user_id, user_key)
        totp_secret = MijAuth.generate_totp_secret()

        # Hash hasła (w produkcji użyj bcrypt lub argon2)
        password_hash = hashlib.sha256(
            (password + 'salt_' + user_id).encode('utf-8')
        ).hexdigest()

        user = {
            'id': user_id,
            'email': email,
            'password_hash': password_hash,
            'encryption_key': user_key,
            'auth_token': token,
            'totp_secret': totp_secret,
            'created_at': datetime.utcnow().isoformat() + 'Z'
        }

        self.users[user_id] = user
        self._save()

        return user, file_content

    def get_user(self, user_id: str) -> Optional[Dict]:
        """Pobiera użytkownika po ID"""
        return self.users.get(user_id)

    def get_user_by_email(self, email: str) -> Optional[Dict]:
        """Pobiera użytkownika po email"""
        for user in self.users.values():
            if user['email'] == email:
                return user
        return None

    def verify_password(self, user: Dict, password: str) -> bool:
        """Weryfikuje hasło użytkownika"""
        password_hash = hashlib.sha256(
            (password + 'salt_' + user['id']).encode('utf-8')
        ).hexdigest()
        return secrets.compare_digest(password_hash, user['password_hash'])

    def update_auth_token(self, user_id: str, new_token: str) -> None:
        """Aktualizuje token autoryzacji użytkownika"""
        if user_id in self.users:
            self.users[user_id]['auth_token'] = new_token
            self._save()

    def delete_storage(self) -> None:
        """Usuwa plik storage"""
        if os.path.exists(self.storage_file):
            os.remove(self.storage_file)

<?php
/**
 * MijAuth - File-Based Two-Factor Authentication System
 * 
 * @package   MijAuth
 * @author    MijagiKutasamoto
 * @license   MIT
 * @link      https://github.com/MijagiKutasamoto/mijauth
 */

declare(strict_types=1);

namespace MijAuth;

use RuntimeException;
use JsonException;

/**
 * Main MijAuth class for file-based 2FA authentication
 */
class MijAuth
{
    private const CIPHER = 'aes-256-gcm';
    private const KEY_LENGTH = 32; // 256 bits
    private const IV_LENGTH = 12;  // 96 bits for GCM
    private const TAG_LENGTH = 16; // 128 bits
    private const VERSION = 1;
    private const LIB_VERSION = '0.4.0';
    private const DEFAULT_AUTH_FILE_TTL_SECONDS = 2592000; // 30 days
    private const DEFAULT_TOTP_PERIOD = 30;
    private const DEFAULT_TOTP_DIGITS = 6;
    private const DEFAULT_TOTP_ALGORITHM = 'SHA1';
    private const DEVICE_ID_COOKIE_NAME = 'mijauth_device_id';

    /**
     * Generate a new AES-256 key for a user
     * 
     * @return string Base64 encoded key
     * @throws RuntimeException If random bytes generation fails
     */
    public static function generateUserKey(): string
    {
        $key = random_bytes(self::KEY_LENGTH);
        return base64_encode($key);
    }

    /**
     * Generate a unique token for a user
     * 
     * @return string Hex encoded token
     */
    public static function generateToken(): string
    {
        return bin2hex(random_bytes(32));
    }

    /**
     * Create an encrypted .mijauth authorization file
     * 
     * @param string $userId User identifier
     * @param string $userKeyBase64 User's encryption key in base64
        * @param string|null $deviceHash Optional device fingerprint hash (v1)
        * @param string|null $deviceHashV2 Optional device fingerprint hash (v2)
     * @return array{file_content: string, token: string}
     * @throws RuntimeException|JsonException
     */
    public static function createAuthFile(
        string $userId,
        string $userKeyBase64,
        ?string $deviceHash = null,
        ?string $deviceHashV2 = null
    ): array {
        $token = self::generateToken();
        
        $payload = [
            'user_id' => $userId,
            'token' => $token,
            'created_at' => date('c'),
            'device_hash' => $deviceHash,
            'device_hash_v2' => $deviceHashV2,
            'version' => self::VERSION
        ];

        $jsonPayload = json_encode($payload, JSON_THROW_ON_ERROR);
        $encryptedContent = self::encrypt($jsonPayload, $userKeyBase64);

        return [
            'file_content' => $encryptedContent,
            'token' => $token
        ];
    }

    /**
     * Verify an authorization file and return user data
     * 
     * @param string $fileContent Content of .mijauth file
     * @param string $userKeyBase64 User's encryption key in base64
     * @return array|null User data or null if verification failed
     */
    public static function verifyAuthFile(
        string $fileContent,
        string $userKeyBase64,
        ?int $maxAgeSeconds = self::DEFAULT_AUTH_FILE_TTL_SECONDS
    ): ?array {
        try {
            $decrypted = self::decrypt($fileContent, $userKeyBase64);
            
            if ($decrypted === null) {
                return null;
            }

            $payload = json_decode($decrypted, true, 512, JSON_THROW_ON_ERROR);
            
            // Validate structure
            if (!isset($payload['user_id'], $payload['token'], $payload['version'])) {
                return null;
            }

            if (!self::isAuthFileWithinTtl($payload, $maxAgeSeconds)) {
                return null;
            }

            return $payload;
        } catch (JsonException | RuntimeException $e) {
            return null;
        }
    }

    /**
     * Verify file and check if token matches the stored one
     * 
     * @param string $fileContent Content of .mijauth file
     * @param string $userKeyBase64 User's encryption key in base64
     * @param string $expectedToken Expected token from database
     * @param string $expectedUserId Expected user ID
     * @return bool
     */
    public static function verifyAuthFileWithToken(
        string $fileContent,
        string $userKeyBase64,
        string $expectedToken,
        string $expectedUserId,
        ?int $maxAgeSeconds = self::DEFAULT_AUTH_FILE_TTL_SECONDS
    ): bool {
        $payload = self::verifyAuthFile($fileContent, $userKeyBase64, $maxAgeSeconds);
        
        if ($payload === null) {
            return false;
        }

        // Constant-time comparison to prevent timing attacks
        return hash_equals($expectedToken, $payload['token']) 
            && hash_equals($expectedUserId, $payload['user_id']);
    }

    /**
     * Verify file and check token/user/device hashes (v2 supported)
     *
     * @param string $fileContent Content of .mijauth file
     * @param string $userKeyBase64 User's encryption key in base64
     * @param string $expectedToken Expected token from database
     * @param string $expectedUserId Expected user ID
     * @param string|null $expectedDeviceHash Expected device hash (v1)
     * @param string|null $expectedDeviceHashV2 Expected device hash (v2)
     * @return bool
     */
    public static function verifyAuthFileWithTokenAndDevice(
        string $fileContent,
        string $userKeyBase64,
        string $expectedToken,
        string $expectedUserId,
        ?string $expectedDeviceHash = null,
        ?string $expectedDeviceHashV2 = null,
        ?int $maxAgeSeconds = self::DEFAULT_AUTH_FILE_TTL_SECONDS
    ): bool {
        $payload = self::verifyAuthFile($fileContent, $userKeyBase64, $maxAgeSeconds);

        if ($payload === null) {
            return false;
        }

        if (!hash_equals($expectedToken, $payload['token'])
            || !hash_equals($expectedUserId, $payload['user_id'])) {
            return false;
        }

        if ($expectedDeviceHash !== null) {
            if (!isset($payload['device_hash'])
                || !hash_equals($expectedDeviceHash, (string) $payload['device_hash'])) {
                return false;
            }
        }

        if ($expectedDeviceHashV2 !== null) {
            if (!isset($payload['device_hash_v2'])
                || !hash_equals($expectedDeviceHashV2, (string) $payload['device_hash_v2'])) {
                return false;
            }
        }

        return true;
    }

    /**
     * Regenerate authorization file (creates new token, invalidates old file)
     * 
     * @param string $userId User identifier
     * @param string $userKeyBase64 User's encryption key in base64
        * @param string|null $deviceHash Optional device fingerprint hash (v1)
        * @param string|null $deviceHashV2 Optional device fingerprint hash (v2)
     * @return array{file_content: string, token: string}
     */
    public static function regenerateAuthFile(
        string $userId,
        string $userKeyBase64,
        ?string $deviceHash = null,
        ?string $deviceHashV2 = null
    ): array {
        return self::createAuthFile($userId, $userKeyBase64, $deviceHash, $deviceHashV2);
    }

    /**
     * Generate a device hash based on available information
     * 
     * @param string $userAgent User-Agent header
     * @param string $acceptLanguage Accept-Language header
     * @param array $additionalData Additional data to include in hash
     * @return string SHA-256 hash of device info
     */
    public static function generateDeviceHash(
        string $userAgent = '',
        string $acceptLanguage = '',
        array $additionalData = []
    ): string {
        $data = array_merge([
            'user_agent' => self::normalizeUserAgent($userAgent),
            'accept_language' => $acceptLanguage,
        ], $additionalData);

        return hash('sha256', json_encode($data));
    }

    /**
     * Generate device hash from current request (for web applications)
     * 
     * @return string SHA-256 hash of device info
     */
    public static function generateDeviceHashFromRequest(): string
    {
        return self::generateDeviceHash(
            $_SERVER['HTTP_USER_AGENT'] ?? '',
            $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
            [
                'device_id' => $_COOKIE[self::DEVICE_ID_COOKIE_NAME] ?? '',
                'platform' => PHP_OS_FAMILY
            ]
        );
    }

    /**
     * Generate stable random device identifier (for device cookie)
     *
     * @return string
     */
    public static function generateDeviceId(): string
    {
        return bin2hex(random_bytes(16));
    }

    /**
     * Generate Base32 TOTP secret (RFC 4226/6238)
     *
     * @param int $length Length in Base32 chars (32 chars ~= 160 bits)
     * @return string
     */
    public static function generateTotpSecret(int $length = 32): string
    {
        if ($length < 16) {
            throw new RuntimeException('TOTP secret length must be at least 16 Base32 chars');
        }

        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $bytes = random_bytes($length);
        $secret = '';

        for ($i = 0; $i < $length; $i++) {
            $secret .= $alphabet[ord($bytes[$i]) % 32];
        }

        return $secret;
    }

    /**
     * Build otpauth provisioning URI for authenticator apps
     *
     * @param string $accountName e.g. user@example.com
     * @param string $issuer e.g. MijAuth Demo
     * @param string $secret Base32 secret
     * @param int $digits TOTP digits
     * @param int $period TOTP period in seconds
     * @param string $algorithm SHA1|SHA256|SHA512
     * @return string
     */
    public static function getTotpProvisioningUri(
        string $accountName,
        string $issuer,
        string $secret,
        int $digits = self::DEFAULT_TOTP_DIGITS,
        int $period = self::DEFAULT_TOTP_PERIOD,
        string $algorithm = self::DEFAULT_TOTP_ALGORITHM
    ): string {
        $normalizedAlgorithm = self::normalizeTotpAlgorithm($algorithm);
        $label = rawurlencode($issuer . ':' . $accountName);

        $query = http_build_query([
            'secret' => strtoupper($secret),
            'issuer' => $issuer,
            'algorithm' => $normalizedAlgorithm,
            'digits' => $digits,
            'period' => $period
        ]);

        return 'otpauth://totp/' . $label . '?' . $query;
    }

    /**
     * Convenience URL for QR rendering (Google Chart API)
     *
     * @param string $provisioningUri otpauth URI
     * @param int $size QR image size
     * @return string
     */
    public static function getTotpQrCodeUrl(string $provisioningUri, int $size = 220): string
    {
        $safeSize = max(100, min(600, $size));
        return 'https://chart.googleapis.com/chart?cht=qr&chs=' . $safeSize . 'x' . $safeSize
            . '&chl=' . rawurlencode($provisioningUri);
    }

    /**
     * Generate TOTP code for current time window
     *
     * @param string $secret Base32 secret
     * @param int|null $timestamp Unix timestamp
     * @param int $period Time step in seconds
     * @param int $digits OTP digits
     * @param string $algorithm SHA1|SHA256|SHA512
     * @return string
     */
    public static function generateTotpCode(
        string $secret,
        ?int $timestamp = null,
        int $period = self::DEFAULT_TOTP_PERIOD,
        int $digits = self::DEFAULT_TOTP_DIGITS,
        string $algorithm = self::DEFAULT_TOTP_ALGORITHM
    ): string {
        $time = $timestamp ?? time();
        $counter = intdiv($time, $period);

        return self::calculateHotp($secret, $counter, $digits, $algorithm);
    }

    /**
     * Verify TOTP code in a configurable time window
     *
     * @param string $secret Base32 secret
     * @param string $code User provided OTP
     * @param int $discrepancy Allowed time windows on both sides
     * @param int|null $timestamp Unix timestamp
     * @param int $period Time step in seconds
     * @param int $digits OTP digits
     * @param string $algorithm SHA1|SHA256|SHA512
     * @return bool
     */
    public static function verifyTotp(
        string $secret,
        string $code,
        int $discrepancy = 1,
        ?int $timestamp = null,
        int $period = self::DEFAULT_TOTP_PERIOD,
        int $digits = self::DEFAULT_TOTP_DIGITS,
        string $algorithm = self::DEFAULT_TOTP_ALGORITHM
    ): bool {
        $normalizedCode = preg_replace('/\s+/', '', $code) ?? '';

        if (!preg_match('/^\d{' . $digits . '}$/', $normalizedCode)) {
            return false;
        }

        $time = $timestamp ?? time();
        $counter = intdiv($time, $period);

        for ($offset = -$discrepancy; $offset <= $discrepancy; $offset++) {
            $candidate = self::calculateHotp($secret, $counter + $offset, $digits, $algorithm);

            if (hash_equals($candidate, $normalizedCode)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Generate device hash v2 based on extended context
     *
     * @param array $context Extended device context
     * @return string SHA-256 hash of device info
     */
    public static function generateDeviceHashV2(array $context = []): string
    {
        $normalized = self::normalizeFingerprintContext($context);

        return hash('sha256', json_encode(
            $normalized,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        ));
    }

    /**
     * Generate device hash v2 from current request
     *
     * @param array $additionalData Additional data to include (e.g. timezone, screen)
     * @return string SHA-256 hash of device info
     */
    public static function generateDeviceHashV2FromRequest(array $additionalData = []): string
    {
        $context = array_merge([
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'accept_language' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
            'accept' => $_SERVER['HTTP_ACCEPT'] ?? '',
            'accept_encoding' => $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '',
            'dnt' => $_SERVER['HTTP_DNT'] ?? '',
            'sec_ch_ua' => $_SERVER['HTTP_SEC_CH_UA'] ?? '',
            'sec_ch_ua_mobile' => $_SERVER['HTTP_SEC_CH_UA_MOBILE'] ?? '',
            'sec_ch_ua_platform' => $_SERVER['HTTP_SEC_CH_UA_PLATFORM'] ?? '',
            'ip' => $_SERVER['REMOTE_ADDR'] ?? ''
        ], $additionalData);

        return self::generateDeviceHashV2($context);
    }

    /**
     * Encrypt data using AES-256-GCM
     * 
     * @param string $plaintext Data to encrypt
     * @param string $keyBase64 Key in base64 format
     * @return string Base64 encoded encrypted data
     * @throws RuntimeException If encryption fails
     */
    private static function encrypt(string $plaintext, string $keyBase64): string
    {
        $key = base64_decode($keyBase64, true);
        if ($key === false || strlen($key) !== self::KEY_LENGTH) {
            throw new RuntimeException('Invalid encryption key');
        }
        $iv = random_bytes(self::IV_LENGTH);
        $tag = '';

        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            self::TAG_LENGTH
        );

        if ($ciphertext === false) {
            throw new RuntimeException('Encryption failed: ' . openssl_error_string());
        }

        // Format: IV (12 bytes) + Tag (16 bytes) + Ciphertext
        $combined = $iv . $tag . $ciphertext;
        
        return base64_encode($combined);
    }

    /**
     * Decrypt data using AES-256-GCM
     * 
     * @param string $encryptedBase64 Base64 encoded encrypted data
     * @param string $keyBase64 Key in base64 format
     * @return string|null Decrypted data or null on failure
     */
    private static function decrypt(string $encryptedBase64, string $keyBase64): ?string
    {
        $key = base64_decode($keyBase64, true);
        if ($key === false || strlen($key) !== self::KEY_LENGTH) {
            return null;
        }

        $combined = base64_decode($encryptedBase64, true);

        if ($combined === false) {
            return null;
        }

        if (strlen($combined) < self::IV_LENGTH + self::TAG_LENGTH) {
            return null;
        }

        $iv = substr($combined, 0, self::IV_LENGTH);
        $tag = substr($combined, self::IV_LENGTH, self::TAG_LENGTH);
        $ciphertext = substr($combined, self::IV_LENGTH + self::TAG_LENGTH);

        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        return $plaintext !== false ? $plaintext : null;
    }

    /**
     * Get the current library version
     * 
     * @return int
     */
    public static function getVersion(): int
    {
        return self::VERSION;
    }

    /**
     * Get the current library version
     *
     * @return string
     */
    public static function getLibraryVersion(): string
    {
        return self::LIB_VERSION;
    }

    /**
     * Normalize fingerprint context (sort keys, remove nulls)
     *
     * @param array $context
     * @return array
     */
    private static function normalizeFingerprintContext(array $context): array
    {
        $normalized = [];

        foreach ($context as $key => $value) {
            if ($value === null) {
                continue;
            }

            if (is_array($value)) {
                $value = self::normalizeFingerprintContext($value);
            }

            $normalized[$key] = $value;
        }

        ksort($normalized);

        return $normalized;
    }

    /**
     * @param array $payload
     * @param int|null $maxAgeSeconds
     * @return bool
     */
    private static function isAuthFileWithinTtl(array $payload, ?int $maxAgeSeconds): bool
    {
        if ($maxAgeSeconds === null) {
            return true;
        }

        if (!isset($payload['created_at']) || !is_string($payload['created_at'])) {
            return false;
        }

        $createdAt = strtotime($payload['created_at']);

        if ($createdAt === false) {
            return false;
        }

        if ($createdAt > time()) {
            return false;
        }

        return (time() - $createdAt) <= $maxAgeSeconds;
    }

    /**
     * @param string $userAgent
     * @return string
     */
    private static function normalizeUserAgent(string $userAgent): string
    {
        if ($userAgent === '') {
            return '';
        }

        if (preg_match('/(Chrome|Firefox|Safari|Edg|OPR)\/(\d+)/i', $userAgent, $matches)) {
            return strtoupper($matches[1]) . '/' . $matches[2];
        }

        return substr($userAgent, 0, 80);
    }

    /**
     * @param string $secret
     * @param int $counter
     * @param int $digits
     * @param string $algorithm
     * @return string
     */
    private static function calculateHotp(
        string $secret,
        int $counter,
        int $digits,
        string $algorithm
    ): string {
        if ($counter < 0) {
            return str_repeat('0', $digits);
        }

        $binarySecret = self::base32Decode($secret);

        if ($binarySecret === '') {
            throw new RuntimeException('Invalid TOTP secret');
        }

        $normalizedAlgorithm = strtolower(self::normalizeTotpAlgorithm($algorithm));
        $counterBinary = pack('N*', 0, $counter);
        $hash = hash_hmac($normalizedAlgorithm, $counterBinary, $binarySecret, true);
        $offset = ord(substr($hash, -1)) & 0x0F;

        $truncated = (
            ((ord($hash[$offset]) & 0x7F) << 24)
            | ((ord($hash[$offset + 1]) & 0xFF) << 16)
            | ((ord($hash[$offset + 2]) & 0xFF) << 8)
            | (ord($hash[$offset + 3]) & 0xFF)
        );

        $otp = (string) ($truncated % (10 ** $digits));

        return str_pad($otp, $digits, '0', STR_PAD_LEFT);
    }

    /**
     * @param string $secret
     * @return string
     */
    private static function base32Decode(string $secret): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $lookup = array_flip(str_split($alphabet));
        $normalized = strtoupper(str_replace('=', '', preg_replace('/\s+/', '', $secret) ?? ''));

        if ($normalized === '') {
            return '';
        }

        $bits = '';

        foreach (str_split($normalized) as $char) {
            if (!isset($lookup[$char])) {
                return '';
            }

            $bits .= str_pad(decbin($lookup[$char]), 5, '0', STR_PAD_LEFT);
        }

        $decoded = '';
        $length = strlen($bits);

        for ($i = 0; $i + 8 <= $length; $i += 8) {
            $decoded .= chr(bindec(substr($bits, $i, 8)));
        }

        return $decoded;
    }

    /**
     * @param string $algorithm
     * @return string
     */
    private static function normalizeTotpAlgorithm(string $algorithm): string
    {
        $normalized = strtoupper(trim($algorithm));
        $allowed = ['SHA1', 'SHA256', 'SHA512'];

        if (!in_array($normalized, $allowed, true)) {
            throw new RuntimeException('Unsupported TOTP algorithm');
        }

        return $normalized;
    }
}

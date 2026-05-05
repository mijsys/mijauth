<?php
/**
 * MijAuth - Authentication Manager
 * 
 * @package   MijAuth
 * @author    MijagiKutasamoto
 * @license   MIT
 */

declare(strict_types=1);

namespace MijAuth;

use MijAuth\Storage\UserStorageInterface;
use MijAuth\Storage\JsonFileStorage;
use MijAuth\Logging\AttemptLoggerInterface;
use MijAuth\Logging\NullAttemptLogger;

/**
 * High-level authentication manager that combines user storage with MijAuth
 */
class AuthManager
{
    private UserStorageInterface $storage;
    private AttemptLoggerInterface $attemptLogger;

    /**
     * @param UserStorageInterface|null $storage User storage implementation
     * @param AttemptLoggerInterface|null $attemptLogger Attempt logger
     */
    public function __construct(
        ?UserStorageInterface $storage = null,
        ?AttemptLoggerInterface $attemptLogger = null
    )
    {
        $this->storage = $storage ?? new JsonFileStorage();
        $this->attemptLogger = $attemptLogger ?? new NullAttemptLogger();
    }

    /**
     * Register a new user and generate their auth file
     * 
     * @param string $userId Unique user identifier
     * @param string $email User's email
     * @param string $password Plain text password (will be hashed)
     * @param string|null $deviceHash Optional device fingerprint (v1)
     * @param string|null $deviceHashV2 Optional device fingerprint (v2)
     * @return array{user: array, auth_file: string}
     */
    public function registerUser(
        string $userId,
        string $email,
        string $password,
        ?string $deviceHash = null,
        ?string $deviceHashV2 = null
    ): array {
        $userKey = MijAuth::generateUserKey();
        $authResult = MijAuth::createAuthFile($userId, $userKey, $deviceHash, $deviceHashV2);

        $user = [
            'id' => $userId,
            'email' => $email,
            'password_hash' => password_hash($password, PASSWORD_ARGON2ID),
            'encryption_key' => $userKey,
            'auth_token' => $authResult['token'],
            'device_hash' => $deviceHash,
            'device_hash_v2' => $deviceHashV2,
            'created_at' => date('c')
        ];

        $this->storage->save($userId, $user);

        return [
            'user' => $user,
            'auth_file' => $authResult['file_content']
        ];
    }

    /**
     * Verify password (Step 1 of login)
     * 
     * @param string $email User's email
     * @param string $password Password to verify
     * @return array|null User data if password is valid, null otherwise
     */
    public function verifyPassword(string $email, string $password): ?array
    {
        $user = $this->storage->findByEmail($email);
        
        if ($user === null) {
            $this->logAttempt('password_verification', false, [
                'email' => $email
            ]);
            return null;
        }

        if (!password_verify($password, $user['password_hash'])) {
            $this->logAttempt('password_verification', false, [
                'email' => $email,
                'user_id' => $user['id'] ?? null
            ]);
            return null;
        }

        $this->logAttempt('password_verification', true, [
            'email' => $email,
            'user_id' => $user['id'] ?? null
        ]);

        return $user;
    }

    /**
     * Verify auth file (Step 2 of login)
     * 
     * @param string $userId User ID from step 1
     * @param string $fileContent Content of uploaded .mijauth file
     * @return bool
     */
    public function verifyAuthFile(string $userId, string $fileContent): bool
    {
        $user = $this->storage->findById($userId);
        
        if ($user === null) {
            $this->logAttempt('auth_file_verification', false, [
                'user_id' => $userId,
                'file_size' => strlen($fileContent)
            ]);
            return false;
        }

        $deviceHash = $user['device_hash'] ?? null;
        $deviceHashV2 = $user['device_hash_v2'] ?? null;

        if ($deviceHash !== null || $deviceHashV2 !== null) {
            $result = MijAuth::verifyAuthFileWithTokenAndDevice(
                $fileContent,
                $user['encryption_key'],
                $user['auth_token'],
                $user['id'],
                $deviceHash,
                $deviceHashV2
            );
        } else {
            $result = MijAuth::verifyAuthFileWithToken(
                $fileContent,
                $user['encryption_key'],
                $user['auth_token'],
                $user['id']
            );
        }

        $this->logAttempt('auth_file_verification', $result, [
            'user_id' => $user['id'],
            'file_size' => strlen($fileContent)
        ]);

        return $result;
    }

    /**
     * Complete two-factor login
     * 
     * @param string $email User's email
     * @param string $password Password
     * @param string $authFileContent Content of .mijauth file
     * @return array|null User data if login successful, null otherwise
     */
    public function login(string $email, string $password, string $authFileContent): ?array
    {
        // Step 1: Verify password
        $user = $this->verifyPassword($email, $password);
        if ($user === null) {
            $this->logAttempt('login', false, [
                'email' => $email
            ]);
            return null;
        }

        // Step 2: Verify auth file
        if (!$this->verifyAuthFile($user['id'], $authFileContent)) {
            $this->logAttempt('login', false, [
                'email' => $email,
                'user_id' => $user['id'] ?? null
            ]);
            return null;
        }

        $this->logAttempt('login', true, [
            'email' => $email,
            'user_id' => $user['id'] ?? null
        ]);

        return $user;
    }

    /**
     * Regenerate auth file for a user (invalidates old file)
     * 
     * @param string $userId User ID
     * @param string|null $deviceHash Optional new device fingerprint (v1)
     * @param string|null $deviceHashV2 Optional new device fingerprint (v2)
     * @return string|null New auth file content, or null if user not found
     */
    public function regenerateAuthFile(
        string $userId,
        ?string $deviceHash = null,
        ?string $deviceHashV2 = null
    ): ?string
    {
        $user = $this->storage->findById($userId);
        
        if ($user === null) {
            return null;
        }

        $authResult = MijAuth::regenerateAuthFile(
            $userId,
            $user['encryption_key'],
            $deviceHash,
            $deviceHashV2
        );

        $this->storage->updateAuthToken($userId, $authResult['token']);

        if ($deviceHash !== null || $deviceHashV2 !== null) {
            $user['device_hash'] = $deviceHash;
            $user['device_hash_v2'] = $deviceHashV2;
            $this->storage->save($userId, $user);
        }

        return $authResult['file_content'];
    }

    /**
     * Get user by ID
     * 
     * @param string $userId
     * @return array|null
     */
    public function getUser(string $userId): ?array
    {
        return $this->storage->findById($userId);
    }

    /**
     * Get user by email
     * 
     * @param string $email
     * @return array|null
     */
    public function getUserByEmail(string $email): ?array
    {
        return $this->storage->findByEmail($email);
    }

    /**
     * Get the storage instance
     * 
     * @return UserStorageInterface
     */
    public function getStorage(): UserStorageInterface
    {
        return $this->storage;
    }

    /**
     * Log authorization attempt
     *
     * @param string $event
     * @param bool $success
     * @param array $context
     * @return void
     */
    private function logAttempt(string $event, bool $success, array $context = []): void
    {
        $payload = array_merge([
            'event' => $event,
            'success' => $success,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? null,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
            'occurred_at' => date('c')
        ], $context);

        $this->attemptLogger->logAttempt($payload);
    }
}

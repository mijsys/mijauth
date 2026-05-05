/**
 * MijAuth - System Weryfikacji Dwuetapowej (2FA) oparty na plikach
 * Implementacja .NET (C#)
 * 
 * Wymaga .NET 6.0+
 */

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace MijAuth
{
    /// <summary>
    /// Główna klasa systemu MijAuth do weryfikacji dwuetapowej
    /// </summary>
    public static class MijAuthService
    {
        private const int KeyLength = 32;  // 256 bits
        private const int IvLength = 12;   // 96 bits dla GCM
        private const int TagLength = 16;  // 128 bits
        private const int Version = 1;

        /// <summary>
        /// Generuje nowy klucz AES-256 dla użytkownika
        /// </summary>
        /// <returns>Klucz w formacie base64</returns>
        public static string GenerateUserKey()
        {
            var key = new byte[KeyLength];
            RandomNumberGenerator.Fill(key);
            return Convert.ToBase64String(key);
        }

        /// <summary>
        /// Generuje unikalny token dla użytkownika
        /// </summary>
        /// <returns>Token w formacie hex</returns>
        public static string GenerateToken()
        {
            var token = new byte[32];
            RandomNumberGenerator.Fill(token);
            return Convert.ToHexString(token).ToLowerInvariant();
        }

        /// <summary>
        /// Tworzy zaszyfrowany plik autoryzacyjny .mijauth
        /// </summary>
        /// <param name="userId">Identyfikator użytkownika</param>
        /// <param name="userKeyBase64">Klucz użytkownika w base64</param>
        /// <param name="deviceHash">Opcjonalny hash urządzenia</param>
        /// <returns>Tuple z zawartością pliku i tokenem</returns>
        public static (string FileContent, string Token) CreateAuthFile(
            string userId,
            string userKeyBase64,
            string? deviceHash = null,
            string? deviceHashV2 = null)
        {
            var token = GenerateToken();

            var payload = new AuthPayload
            {
                UserId = userId,
                Token = token,
                CreatedAt = DateTime.UtcNow.ToString("o"),
                DeviceHash = deviceHash,
                DeviceHashV2 = deviceHashV2,
                Version = Version
            };

            var jsonPayload = JsonSerializer.Serialize(payload);
            var encryptedContent = Encrypt(jsonPayload, userKeyBase64);

            return (encryptedContent, token);
        }

        /// <summary>
        /// Weryfikuje plik autoryzacyjny i zwraca dane użytkownika
        /// </summary>
        /// <param name="fileContent">Zawartość pliku .mijauth</param>
        /// <param name="userKeyBase64">Klucz użytkownika w base64</param>
        /// <returns>Dane użytkownika lub null</returns>
        public static AuthPayload? VerifyAuthFile(string fileContent, string userKeyBase64)
        {
            try
            {
                var decrypted = Decrypt(fileContent, userKeyBase64);

                if (decrypted == null)
                    return null;

                var payload = JsonSerializer.Deserialize<AuthPayload>(decrypted);

                // Walidacja struktury
                if (payload == null || 
                    string.IsNullOrEmpty(payload.UserId) || 
                    string.IsNullOrEmpty(payload.Token))
                {
                    return null;
                }

                return payload;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Weryfikuje plik i sprawdza czy token zgadza się z przechowywanym
        /// </summary>
        /// <param name="fileContent">Zawartość pliku .mijauth</param>
        /// <param name="userKeyBase64">Klucz użytkownika w base64</param>
        /// <param name="expectedToken">Oczekiwany token z bazy danych</param>
        /// <param name="expectedUserId">Oczekiwane ID użytkownika</param>
        /// <returns>True jeśli weryfikacja pomyślna</returns>
        public static bool VerifyAuthFileWithToken(
            string fileContent,
            string userKeyBase64,
            string expectedToken,
            string expectedUserId)
        {
            var payload = VerifyAuthFile(fileContent, userKeyBase64);

            if (payload == null)
                return false;

            // Constant-time comparison
            return CryptographicOperations.FixedTimeEquals(
                       Encoding.UTF8.GetBytes(expectedToken),
                       Encoding.UTF8.GetBytes(payload.Token)) &&
                   CryptographicOperations.FixedTimeEquals(
                       Encoding.UTF8.GetBytes(expectedUserId),
                       Encoding.UTF8.GetBytes(payload.UserId));
        }

        /// <summary>
        /// Weryfikuje plik, token i hash urządzenia (v1/v2)
        /// </summary>
        public static bool VerifyAuthFileWithTokenAndDevice(
            string fileContent,
            string userKeyBase64,
            string expectedToken,
            string expectedUserId,
            string? expectedDeviceHash = null,
            string? expectedDeviceHashV2 = null)
        {
            var payload = VerifyAuthFile(fileContent, userKeyBase64);

            if (payload == null)
                return false;

            var tokenMatch = CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(expectedToken),
                Encoding.UTF8.GetBytes(payload.Token));

            var userMatch = CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(expectedUserId),
                Encoding.UTF8.GetBytes(payload.UserId));

            if (!tokenMatch || !userMatch)
                return false;

            if (expectedDeviceHash != null)
            {
                if (string.IsNullOrEmpty(payload.DeviceHash))
                    return false;

                if (!CryptographicOperations.FixedTimeEquals(
                        Encoding.UTF8.GetBytes(expectedDeviceHash),
                        Encoding.UTF8.GetBytes(payload.DeviceHash)))
                    return false;
            }

            if (expectedDeviceHashV2 != null)
            {
                if (string.IsNullOrEmpty(payload.DeviceHashV2))
                    return false;

                if (!CryptographicOperations.FixedTimeEquals(
                        Encoding.UTF8.GetBytes(expectedDeviceHashV2),
                        Encoding.UTF8.GetBytes(payload.DeviceHashV2)))
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Regeneruje plik autoryzacyjny (nowy token)
        /// </summary>
        /// <param name="userId">Identyfikator użytkownika</param>
        /// <param name="userKeyBase64">Klucz użytkownika w base64</param>
        /// <param name="deviceHash">Opcjonalny hash urządzenia</param>
        /// <returns>Tuple z zawartością pliku i tokenem</returns>
        public static (string FileContent, string Token) RegenerateAuthFile(
            string userId,
            string userKeyBase64,
            string? deviceHash = null,
            string? deviceHashV2 = null)
        {
            return CreateAuthFile(userId, userKeyBase64, deviceHash, deviceHashV2);
        }

        /// <summary>
        /// Szyfruje dane przy użyciu AES-256-GCM
        /// </summary>
        private static string Encrypt(string plaintext, string keyBase64)
        {
            var key = Convert.FromBase64String(keyBase64);
            var iv = new byte[IvLength];
            RandomNumberGenerator.Fill(iv);

            var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            var ciphertext = new byte[plaintextBytes.Length];
            var tag = new byte[TagLength];

            using var aes = new AesGcm(key, TagLength);
            aes.Encrypt(iv, plaintextBytes, ciphertext, tag);

            // Format: IV (12 bytes) + Tag (16 bytes) + Ciphertext
            var combined = new byte[iv.Length + tag.Length + ciphertext.Length];
            Buffer.BlockCopy(iv, 0, combined, 0, iv.Length);
            Buffer.BlockCopy(tag, 0, combined, iv.Length, tag.Length);
            Buffer.BlockCopy(ciphertext, 0, combined, iv.Length + tag.Length, ciphertext.Length);

            return Convert.ToBase64String(combined);
        }

        /// <summary>
        /// Odszyfrowuje dane przy użyciu AES-256-GCM
        /// </summary>
        private static string? Decrypt(string encryptedBase64, string keyBase64)
        {
            try
            {
                var key = Convert.FromBase64String(keyBase64);
                var combined = Convert.FromBase64String(encryptedBase64);

                if (combined.Length < IvLength + TagLength)
                    return null;

                var iv = new byte[IvLength];
                var tag = new byte[TagLength];
                var ciphertext = new byte[combined.Length - IvLength - TagLength];

                Buffer.BlockCopy(combined, 0, iv, 0, IvLength);
                Buffer.BlockCopy(combined, IvLength, tag, 0, TagLength);
                Buffer.BlockCopy(combined, IvLength + TagLength, ciphertext, 0, ciphertext.Length);

                var plaintext = new byte[ciphertext.Length];

                using var aes = new AesGcm(key, TagLength);
                aes.Decrypt(iv, ciphertext, tag, plaintext);

                return Encoding.UTF8.GetString(plaintext);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Generuje hash urządzenia na podstawie headers
        /// </summary>
        public static string GenerateDeviceHash(string userAgent, string acceptLanguage)
        {
            var data = JsonSerializer.Serialize(new { userAgent, acceptLanguage });
            var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(data));
            return Convert.ToHexString(bytes).ToLowerInvariant();
        }

        /// <summary>
        /// Generuje hash urządzenia v2 z kontekstu
        /// </summary>
        public static string GenerateDeviceHashV2(Dictionary<string, object?> context)
        {
            var normalized = NormalizeFingerprintContext(context);
            var json = JsonSerializer.Serialize(normalized);
            var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(json));
            return Convert.ToHexString(bytes).ToLowerInvariant();
        }

        private static Dictionary<string, object?> NormalizeFingerprintContext(Dictionary<string, object?> context)
        {
            var normalized = new SortedDictionary<string, object?>();
            foreach (var entry in context)
            {
                if (entry.Value == null)
                    continue;

                if (entry.Value is Dictionary<string, object?> nested)
                {
                    normalized[entry.Key] = NormalizeFingerprintContext(nested);
                }
                else
                {
                    normalized[entry.Key] = entry.Value;
                }
            }

            return new Dictionary<string, object?>(normalized);
        }
    }

    /// <summary>
    /// Struktura danych w pliku .mijauth
    /// </summary>
    public class AuthPayload
    {
        public string UserId { get; set; } = "";
        public string Token { get; set; } = "";
        public string CreatedAt { get; set; } = "";
        public string? DeviceHash { get; set; }
        public string? DeviceHashV2 { get; set; }
        public int Version { get; set; }
    }

    /// <summary>
    /// Model użytkownika
    /// </summary>
    public class User
    {
        public string Id { get; set; } = "";
        public string Email { get; set; } = "";
        public string PasswordHash { get; set; } = "";
        public string EncryptionKey { get; set; } = "";
        public string AuthToken { get; set; } = "";
        public string CreatedAt { get; set; } = "";
    }

    /// <summary>
    /// Symulacja bazy danych użytkowników
    /// </summary>
    public class UserDatabase
    {
        private Dictionary<string, User> _users = new();
        private readonly string _storageFile;

        public UserDatabase(string storageFile = "users.json")
        {
            _storageFile = storageFile;
            Load();
        }

        private void Load()
        {
            if (File.Exists(_storageFile))
            {
                var json = File.ReadAllText(_storageFile);
                _users = JsonSerializer.Deserialize<Dictionary<string, User>>(json) ?? new();
            }
        }

        private void Save()
        {
            var json = JsonSerializer.Serialize(_users, new JsonSerializerOptions 
            { 
                WriteIndented = true 
            });
            File.WriteAllText(_storageFile, json);
        }

        public (User User, string AuthFile) CreateUser(string userId, string email, string password)
        {
            var userKey = MijAuthService.GenerateUserKey();
            var (fileContent, token) = MijAuthService.CreateAuthFile(userId, userKey, null, null);

            // Hash hasła (w produkcji użyj BCrypt lub Argon2)
            var passwordHash = Convert.ToHexString(
                SHA256.HashData(Encoding.UTF8.GetBytes(password + "salt_" + userId))
            ).ToLowerInvariant();

            var user = new User
            {
                Id = userId,
                Email = email,
                PasswordHash = passwordHash,
                EncryptionKey = userKey,
                AuthToken = token,
                CreatedAt = DateTime.UtcNow.ToString("o")
            };

            _users[userId] = user;
            Save();

            return (user, fileContent);
        }

        public User? GetUser(string userId)
        {
            return _users.TryGetValue(userId, out var user) ? user : null;
        }

        public User? GetUserByEmail(string email)
        {
            return _users.Values.FirstOrDefault(u => u.Email == email);
        }

        public bool VerifyPassword(User user, string password)
        {
            var hash = Convert.ToHexString(
                SHA256.HashData(Encoding.UTF8.GetBytes(password + "salt_" + user.Id))
            ).ToLowerInvariant();

            return CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(hash),
                Encoding.UTF8.GetBytes(user.PasswordHash)
            );
        }

        public void UpdateAuthToken(string userId, string newToken)
        {
            if (_users.TryGetValue(userId, out var user))
            {
                user.AuthToken = newToken;
                Save();
            }
        }

        public void DeleteStorage()
        {
            if (File.Exists(_storageFile))
                File.Delete(_storageFile);
        }
    }
}

/**
 * MijAuth - Przykład użycia systemu 2FA w .NET
 */

using System.Security.Cryptography;

namespace MijAuth;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("=== MijAuth - System Weryfikacji Dwuetapowej ===\n");

        // Inicjalizacja "bazy danych"
        var db = new UserDatabase("demo_users.json");

        // ========================================
        // KROK 1: Rejestracja użytkownika
        // ========================================
        Console.WriteLine("1. REJESTRACJA UŻYTKOWNIKA");
        Console.WriteLine(new string('-', 50));

        var userId = "user_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();
        var email = "jan.kowalski@example.com";
        var password = "bezpieczne_haslo_123";

        var (user, authFileContent) = db.CreateUser(userId, email, password);

        Console.WriteLine($"✓ Utworzono użytkownika: {email}");
        Console.WriteLine($"✓ ID użytkownika: {userId}");
        Console.WriteLine("✓ Wygenerowano plik .mijauth");

        // Zapisz plik do pobrania
        var authFileName = $"auth_{userId}.mijauth";
        File.WriteAllText(authFileName, authFileContent);
        Console.WriteLine($"✓ Zapisano plik: {authFileName}\n");

        // ========================================
        // KROK 2: Logowanie - krok 1 (hasło)
        // ========================================
        Console.WriteLine("2. LOGOWANIE - ETAP 1 (HASŁO)");
        Console.WriteLine(new string('-', 50));

        var loginEmail = "jan.kowalski@example.com";
        var loginPassword = "bezpieczne_haslo_123";

        var foundUser = db.GetUserByEmail(loginEmail);

        if (foundUser != null && db.VerifyPassword(foundUser, loginPassword))
        {
            Console.WriteLine("✓ Hasło poprawne!");
            Console.WriteLine("→ Wymagana weryfikacja pliku .mijauth\n");
        }
        else
        {
            Console.WriteLine("✗ Nieprawidłowy email lub hasło");
            return;
        }

        // ========================================
        // KROK 3: Logowanie - krok 2 (plik 2FA)
        // ========================================
        Console.WriteLine("3. LOGOWANIE - ETAP 2 (PLIK 2FA)");
        Console.WriteLine(new string('-', 50));

        // Symulacja przesłania pliku przez użytkownika
        var uploadedFileContent = File.ReadAllText(authFileName);

        var isValid = MijAuthService.VerifyAuthFileWithToken(
            uploadedFileContent,
            foundUser.EncryptionKey,
            foundUser.AuthToken,
            foundUser.Id
        );

        if (isValid)
        {
            Console.WriteLine("✓ Weryfikacja 2FA pomyślna!");
            Console.WriteLine($"✓ Użytkownik zalogowany: {foundUser.Email}\n");
        }
        else
        {
            Console.WriteLine("✗ Nieprawidłowy plik autoryzacyjny");
            return;
        }

        // ========================================
        // KROK 4: Regeneracja pliku (opcjonalnie)
        // ========================================
        Console.WriteLine("4. REGENERACJA PLIKU (UNIEWAŻNIENIE STAREGO)");
        Console.WriteLine(new string('-', 50));

        var (newFileContent, newToken) = MijAuthService.RegenerateAuthFile(userId, foundUser.EncryptionKey);
        db.UpdateAuthToken(userId, newToken);

        var newAuthFileName = $"auth_{userId}_new.mijauth";
        File.WriteAllText(newAuthFileName, newFileContent);

        Console.WriteLine($"✓ Wygenerowano nowy plik: {newAuthFileName}");
        Console.WriteLine("✓ Stary plik został unieważniony\n");

        // Test starego pliku (powinien być odrzucony)
        Console.WriteLine("5. TEST STAREGO PLIKU (POWINIEN BYĆ ODRZUCONY)");
        Console.WriteLine(new string('-', 50));

        foundUser = db.GetUser(userId)!; // Odśwież dane
        var isOldValid = MijAuthService.VerifyAuthFileWithToken(
            uploadedFileContent, // Stary plik
            foundUser.EncryptionKey,
            foundUser.AuthToken, // Nowy token
            foundUser.Id
        );

        if (!isOldValid)
        {
            Console.WriteLine("✓ Stary plik poprawnie odrzucony!\n");
        }
        else
        {
            Console.WriteLine("✗ BŁĄD: Stary plik nie powinien działać!");
        }

        // Test nowego pliku
        Console.WriteLine("6. TEST NOWEGO PLIKU");
        Console.WriteLine(new string('-', 50));

        var newUploadedContent = File.ReadAllText(newAuthFileName);
        var isNewValid = MijAuthService.VerifyAuthFileWithToken(
            newUploadedContent,
            foundUser.EncryptionKey,
            foundUser.AuthToken,
            foundUser.Id
        );

        if (isNewValid)
        {
            Console.WriteLine("✓ Nowy plik działa poprawnie!\n");
        }
        else
        {
            Console.WriteLine("✗ BŁĄD: Nowy plik powinien działać!");
        }

        // ========================================
        // Podgląd odszyfrowanej zawartości
        // ========================================
        Console.WriteLine("7. PODGLĄD ODSZYFROWANEJ ZAWARTOŚCI PLIKU");
        Console.WriteLine(new string('-', 50));

        var decryptedData = MijAuthService.VerifyAuthFile(newUploadedContent, foundUser.EncryptionKey);
        Console.WriteLine("Zawartość pliku .mijauth:");
        Console.WriteLine($"  UserId: {decryptedData?.UserId}");
        Console.WriteLine($"  Token: {decryptedData?.Token}");
        Console.WriteLine($"  CreatedAt: {decryptedData?.CreatedAt}");
        Console.WriteLine($"  Version: {decryptedData?.Version}\n");

        // Czyszczenie
        File.Delete(authFileName);
        File.Delete(newAuthFileName);
        db.DeleteStorage();

        Console.WriteLine("=== DEMO ZAKOŃCZONE ===");
    }
}

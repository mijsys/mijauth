<?php
/**
 * MijAuth - Przykład użycia systemu 2FA
 */

require_once 'MijAuth.php';

echo "=== MijAuth - System Weryfikacji Dwuetapowej ===\n\n";

// Inicjalizacja "bazy danych"
$db = new UserDatabase('demo_users.json');

// ========================================
// KROK 1: Rejestracja użytkownika
// ========================================
echo "1. REJESTRACJA UŻYTKOWNIKA\n";
echo str_repeat("-", 50) . "\n";

$userId = 'user_' . bin2hex(random_bytes(8));
$email = 'jan.kowalski@example.com';
$password = 'bezpieczne_haslo_123';
$passwordHash = password_hash($password, PASSWORD_ARGON2ID);

$result = $db->createUser($userId, $email, $passwordHash);
$authFileContent = $result['auth_file'];

echo "✓ Utworzono użytkownika: $email\n";
echo "✓ ID użytkownika: $userId\n";
echo "✓ Wygenerowano plik .mijauth\n";

// Zapisz plik do pobrania
$authFileName = "auth_{$userId}.mijauth";
file_put_contents($authFileName, $authFileContent);
echo "✓ Zapisano plik: $authFileName\n\n";

// ========================================
// KROK 2: Logowanie - krok 1 (hasło)
// ========================================
echo "2. LOGOWANIE - ETAP 1 (HASŁO)\n";
echo str_repeat("-", 50) . "\n";

$loginEmail = 'jan.kowalski@example.com';
$loginPassword = 'bezpieczne_haslo_123';

$user = $db->getUserByEmail($loginEmail);

if ($user && password_verify($loginPassword, $user['password_hash'])) {
    echo "✓ Hasło poprawne!\n";
    echo "→ Wymagana weryfikacja pliku .mijauth\n\n";
} else {
    echo "✗ Nieprawidłowy email lub hasło\n";
    exit(1);
}

// ========================================
// KROK 3: Logowanie - krok 2 (plik 2FA)
// ========================================
echo "3. LOGOWANIE - ETAP 2 (PLIK 2FA)\n";
echo str_repeat("-", 50) . "\n";

// Symulacja przesłania pliku przez użytkownika
$uploadedFileContent = file_get_contents($authFileName);

$isValid = MijAuth::verifyAuthFileWithToken(
    $uploadedFileContent,
    $user['encryption_key'],
    $user['auth_token'],
    $user['id']
);

if ($isValid) {
    echo "✓ Weryfikacja 2FA pomyślna!\n";
    echo "✓ Użytkownik zalogowany: {$user['email']}\n\n";
} else {
    echo "✗ Nieprawidłowy plik autoryzacyjny\n";
    exit(1);
}

// ========================================
// KROK 4: Regeneracja pliku (opcjonalnie)
// ========================================
echo "4. REGENERACJA PLIKU (UNIEWAŻNIENIE STAREGO)\n";
echo str_repeat("-", 50) . "\n";

$newAuthResult = MijAuth::regenerateAuthFile($userId, $user['encryption_key']);
$db->updateAuthToken($userId, $newAuthResult['token']);

$newAuthFileName = "auth_{$userId}_new.mijauth";
file_put_contents($newAuthFileName, $newAuthResult['file_content']);

echo "✓ Wygenerowano nowy plik: $newAuthFileName\n";
echo "✓ Stary plik został unieważniony\n\n";

// Test starego pliku (powinien być odrzucony)
echo "5. TEST STAREGO PLIKU (POWINIEN BYĆ ODRZUCONY)\n";
echo str_repeat("-", 50) . "\n";

$user = $db->getUser($userId); // Odśwież dane
$isOldValid = MijAuth::verifyAuthFileWithToken(
    $uploadedFileContent, // Stary plik
    $user['encryption_key'],
    $user['auth_token'], // Nowy token
    $user['id']
);

if (!$isOldValid) {
    echo "✓ Stary plik poprawnie odrzucony!\n\n";
} else {
    echo "✗ BŁĄD: Stary plik nie powinien działać!\n";
}

// Test nowego pliku
echo "6. TEST NOWEGO PLIKU\n";
echo str_repeat("-", 50) . "\n";

$newFileContent = file_get_contents($newAuthFileName);
$isNewValid = MijAuth::verifyAuthFileWithToken(
    $newFileContent,
    $user['encryption_key'],
    $user['auth_token'],
    $user['id']
);

if ($isNewValid) {
    echo "✓ Nowy plik działa poprawnie!\n\n";
} else {
    echo "✗ BŁĄD: Nowy plik powinien działać!\n";
}

// ========================================
// Podgląd odszyfrowanej zawartości
// ========================================
echo "7. PODGLĄD ODSZYFROWANEJ ZAWARTOŚCI PLIKU\n";
echo str_repeat("-", 50) . "\n";

$decryptedData = MijAuth::verifyAuthFile($newFileContent, $user['encryption_key']);
echo "Zawartość pliku .mijauth:\n";
echo json_encode($decryptedData, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n\n";

// Czyszczenie
unlink($authFileName);
unlink($newAuthFileName);
unlink('demo_users.json');

echo "=== DEMO ZAKOŃCZONE ===\n";

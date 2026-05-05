/**
 * MijAuth - Przykład użycia systemu 2FA w Node.js
 */

const { MijAuth, UserDatabase } = require('./MijAuth');
const fs = require('fs');
const crypto = require('crypto');

async function main() {
    console.log('=== MijAuth - System Weryfikacji Dwuetapowej ===\n');

    // Inicjalizacja "bazy danych"
    const db = new UserDatabase('demo_users.json');

    // ========================================
    // KROK 1: Rejestracja użytkownika
    // ========================================
    console.log('1. REJESTRACJA UŻYTKOWNIKA');
    console.log('-'.repeat(50));

    const userId = 'user_' + crypto.randomBytes(8).toString('hex');
    const email = 'jan.kowalski@example.com';
    const password = 'bezpieczne_haslo_123';

    const result = await db.createUser(userId, email, password);
    const authFileContent = result.authFile;

    console.log(`✓ Utworzono użytkownika: ${email}`);
    console.log(`✓ ID użytkownika: ${userId}`);
    console.log('✓ Wygenerowano plik .mijauth');

    // Zapisz plik do pobrania
    const authFileName = `auth_${userId}.mijauth`;
    fs.writeFileSync(authFileName, authFileContent);
    console.log(`✓ Zapisano plik: ${authFileName}\n`);

    // ========================================
    // KROK 2: Logowanie - krok 1 (hasło)
    // ========================================
    console.log('2. LOGOWANIE - ETAP 1 (HASŁO)');
    console.log('-'.repeat(50));

    const loginEmail = 'jan.kowalski@example.com';
    const loginPassword = 'bezpieczne_haslo_123';

    let user = db.getUserByEmail(loginEmail);

    if (user && db.verifyPassword(user, loginPassword)) {
        console.log('✓ Hasło poprawne!');
        console.log('→ Wymagana weryfikacja pliku .mijauth\n');
    } else {
        console.log('✗ Nieprawidłowy email lub hasło');
        process.exit(1);
    }

    // ========================================
    // KROK 3: Logowanie - krok 2 (plik 2FA)
    // ========================================
    console.log('3. LOGOWANIE - ETAP 2 (PLIK 2FA)');
    console.log('-'.repeat(50));

    // Symulacja przesłania pliku przez użytkownika
    const uploadedFileContent = fs.readFileSync(authFileName, 'utf8');

    const isValid = MijAuth.verifyAuthFileWithToken(
        uploadedFileContent,
        user.encryption_key,
        user.auth_token,
        user.id
    );

    if (isValid) {
        console.log('✓ Weryfikacja 2FA pomyślna!');
        console.log(`✓ Użytkownik zalogowany: ${user.email}\n`);
    } else {
        console.log('✗ Nieprawidłowy plik autoryzacyjny');
        process.exit(1);
    }

    // ========================================
    // KROK 4: Regeneracja pliku (opcjonalnie)
    // ========================================
    console.log('4. REGENERACJA PLIKU (UNIEWAŻNIENIE STAREGO)');
    console.log('-'.repeat(50));

    const newAuthResult = MijAuth.regenerateAuthFile(userId, user.encryption_key);
    db.updateAuthToken(userId, newAuthResult.token);

    const newAuthFileName = `auth_${userId}_new.mijauth`;
    fs.writeFileSync(newAuthFileName, newAuthResult.fileContent);

    console.log(`✓ Wygenerowano nowy plik: ${newAuthFileName}`);
    console.log('✓ Stary plik został unieważniony\n');

    // Test starego pliku (powinien być odrzucony)
    console.log('5. TEST STAREGO PLIKU (POWINIEN BYĆ ODRZUCONY)');
    console.log('-'.repeat(50));

    user = db.getUser(userId); // Odśwież dane
    const isOldValid = MijAuth.verifyAuthFileWithToken(
        uploadedFileContent, // Stary plik
        user.encryption_key,
        user.auth_token, // Nowy token
        user.id
    );

    if (!isOldValid) {
        console.log('✓ Stary plik poprawnie odrzucony!\n');
    } else {
        console.log('✗ BŁĄD: Stary plik nie powinien działać!');
    }

    // Test nowego pliku
    console.log('6. TEST NOWEGO PLIKU');
    console.log('-'.repeat(50));

    const newFileContent = fs.readFileSync(newAuthFileName, 'utf8');
    const isNewValid = MijAuth.verifyAuthFileWithToken(
        newFileContent,
        user.encryption_key,
        user.auth_token,
        user.id
    );

    if (isNewValid) {
        console.log('✓ Nowy plik działa poprawnie!\n');
    } else {
        console.log('✗ BŁĄD: Nowy plik powinien działać!');
    }

    // ========================================
    // Podgląd odszyfrowanej zawartości
    // ========================================
    console.log('7. PODGLĄD ODSZYFROWANEJ ZAWARTOŚCI PLIKU');
    console.log('-'.repeat(50));

    const decryptedData = MijAuth.verifyAuthFile(newFileContent, user.encryption_key);
    console.log('Zawartość pliku .mijauth:');
    console.log(JSON.stringify(decryptedData, null, 2) + '\n');

    // Czyszczenie
    fs.unlinkSync(authFileName);
    fs.unlinkSync(newAuthFileName);
    fs.unlinkSync('demo_users.json');

    console.log('=== DEMO ZAKOŃCZONE ===');
}

main().catch(console.error);

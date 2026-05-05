import java.io.File
import java.security.SecureRandom

fun main() {
    println("=== MijAuth - System Weryfikacji Dwuetapowej (Kotlin) ===\n")

    val db = UserDatabase("demo_users.json")

    println("1. REJESTRACJA UŻYTKOWNIKA")
    println("-".repeat(50))

    val userId = "user_" + randomHex(8)
    val email = "jan.kowalski@example.com"
    val password = "bezpieczne_haslo_123"

    val (user, authFileContent) = db.createUser(userId, email, password)

    println("✓ Utworzono użytkownika: $email")
    println("✓ ID użytkownika: $userId")
    println("✓ Wygenerowano plik .mijauth")
    println("✓ Włączono kod 2FA z aplikacji (TOTP)")

    val authFileName = "auth_${userId}.mijauth"
    File(authFileName).writeText(authFileContent)
    println("✓ Zapisano plik: $authFileName\n")

    println("2. LOGOWANIE - ETAP 1 (HASŁO)")
    println("-".repeat(50))

    val foundUser = db.getUserByEmail(email)
    if (foundUser != null && db.verifyPassword(foundUser, password)) {
        println("✓ Hasło poprawne!")
        println("→ Wymagana weryfikacja pliku .mijauth\n")
    } else {
        println("✗ Nieprawidłowy email lub hasło")
        return
    }

    println("3. LOGOWANIE - ETAP 2 (PLIK 2FA)")
    println("-".repeat(50))

    val uploadedFileContent = File(authFileName).readText()
    val isValid = MijAuth.verifyAuthFileWithToken(
        uploadedFileContent,
        foundUser.encryption_key,
        foundUser.auth_token,
        foundUser.id
    )

    if (isValid) {
        println("✓ Weryfikacja 2FA pomyślna!")
        println("✓ Użytkownik zalogowany: ${foundUser.email}\n")
    } else {
        println("✗ Nieprawidłowy plik autoryzacyjny")
        return
    }

    println("4. LOGOWANIE - ETAP 3 (KOD Z APLIKACJI 2FA)")
    println("-".repeat(50))

    val provisioningUri = MijAuth.getTotpProvisioningUri(foundUser.email, "MijAuth Demo", foundUser.totp_secret)
    val appCode = MijAuth.generateTotpCode(foundUser.totp_secret)
    val isTotpValid = MijAuth.verifyTotp(foundUser.totp_secret, appCode, discrepancy = 1)

    if (isTotpValid) {
        println("✓ Kod TOTP poprawny")
        println("✓ URI do sparowania aplikacji: $provisioningUri\n")
    } else {
        println("✗ Nieprawidłowy kod TOTP")
        return
    }

    println("5. REGENERACJA PLIKU (UNIEWAŻNIENIE STAREGO)")
    println("-".repeat(50))

    val (newFileContent, newToken) = MijAuth.regenerateAuthFile(userId, foundUser.encryption_key)
    db.updateAuthToken(userId, newToken)

    val newAuthFileName = "auth_${userId}_new.mijauth"
    File(newAuthFileName).writeText(newFileContent)

    println("✓ Wygenerowano nowy plik: $newAuthFileName")
    println("✓ Stary plik został unieważniony\n")

    println("6. TEST STAREGO PLIKU (POWINIEN BYĆ ODRZUCONY)")
    println("-".repeat(50))

    val refreshed = db.getUser(userId)!!
    val isOldValid = MijAuth.verifyAuthFileWithToken(
        uploadedFileContent,
        refreshed.encryption_key,
        refreshed.auth_token,
        refreshed.id
    )

    if (!isOldValid) {
        println("✓ Stary plik poprawnie odrzucony!\n")
    } else {
        println("✗ BŁĄD: Stary plik nie powinien działać!")
    }

    println("7. TEST NOWEGO PLIKU")
    println("-".repeat(50))

    val newUploadedContent = File(newAuthFileName).readText()
    val isNewValid = MijAuth.verifyAuthFileWithToken(
        newUploadedContent,
        refreshed.encryption_key,
        refreshed.auth_token,
        refreshed.id
    )

    if (isNewValid) {
        println("✓ Nowy plik działa poprawnie!\n")
    } else {
        println("✗ BŁĄD: Nowy plik powinien działać!")
    }

    println("8. PODGLĄD ODSZYFROWANEJ ZAWARTOŚCI PLIKU")
    println("-".repeat(50))

    val decryptedData = MijAuth.verifyAuthFile(newUploadedContent, refreshed.encryption_key)
    println("Zawartość pliku .mijauth:")
    println(decryptedData)
    println()

    File(authFileName).delete()
    File(newAuthFileName).delete()
    db.deleteStorage()

    println("=== DEMO ZAKOŃCZONE ===")
}

private fun randomHex(bytes: Int): String {
    val buf = ByteArray(bytes)
    SecureRandom().nextBytes(buf)
    return buf.joinToString("") { "%02x".format(it) }
}

// MijAuth - Przykład użycia systemu 2FA w Go
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func main() {
	fmt.Println("=== MijAuth - System Weryfikacji Dwuetapowej ===\n")

	// Inicjalizacja "bazy danych"
	db := NewUserDatabase("demo_users.json")
	auth := &MijAuth{}

	// ========================================
	// KROK 1: Rejestracja użytkownika
	// ========================================
	fmt.Println("1. REJESTRACJA UŻYTKOWNIKA")
	fmt.Println(strings.Repeat("-", 50))

	userID := "user_" + generateRandomHex(8)
	email := "jan.kowalski@example.com"
	password := "bezpieczne_haslo_123"

	user, authFileContent, err := db.CreateUser(userID, email, password)
	if err != nil {
		fmt.Printf("✗ Błąd: %v\n", err)
		return
	}

	fmt.Printf("✓ Utworzono użytkownika: %s\n", email)
	fmt.Printf("✓ ID użytkownika: %s\n", userID)
	fmt.Println("✓ Wygenerowano plik .mijauth")

	// Zapisz plik do pobrania
	authFileName := fmt.Sprintf("auth_%s.mijauth", userID)
	os.WriteFile(authFileName, []byte(authFileContent), 0644)
	fmt.Printf("✓ Zapisano plik: %s\n\n", authFileName)

	// ========================================
	// KROK 2: Logowanie - krok 1 (hasło)
	// ========================================
	fmt.Println("2. LOGOWANIE - ETAP 1 (HASŁO)")
	fmt.Println(strings.Repeat("-", 50))

	loginEmail := "jan.kowalski@example.com"
	loginPassword := "bezpieczne_haslo_123"

	foundUser := db.GetUserByEmail(loginEmail)

	if foundUser != nil && db.VerifyPassword(foundUser, loginPassword) {
		fmt.Println("✓ Hasło poprawne!")
		fmt.Println("→ Wymagana weryfikacja pliku .mijauth\n")
	} else {
		fmt.Println("✗ Nieprawidłowy email lub hasło")
		return
	}

	// ========================================
	// KROK 3: Logowanie - krok 2 (plik 2FA)
	// ========================================
	fmt.Println("3. LOGOWANIE - ETAP 2 (PLIK 2FA)")
	fmt.Println(strings.Repeat("-", 50))

	// Symulacja przesłania pliku przez użytkownika
	uploadedFileContent, _ := os.ReadFile(authFileName)

	isValid := auth.VerifyAuthFileWithToken(
		string(uploadedFileContent),
		foundUser.EncryptionKey,
		foundUser.AuthToken,
		foundUser.ID,
	)

	if isValid {
		fmt.Println("✓ Weryfikacja 2FA pomyślna!")
		fmt.Printf("✓ Użytkownik zalogowany: %s\n\n", foundUser.Email)
	} else {
		fmt.Println("✗ Nieprawidłowy plik autoryzacyjny")
		return
	}

	// ========================================
	// KROK 4: Regeneracja pliku (opcjonalnie)
	// ========================================
	fmt.Println("4. REGENERACJA PLIKU (UNIEWAŻNIENIE STAREGO)")
	fmt.Println(strings.Repeat("-", 50))

	newFileContent, newToken, _ := auth.RegenerateAuthFile(userID, user.EncryptionKey, nil)
	db.UpdateAuthToken(userID, newToken)

	newAuthFileName := fmt.Sprintf("auth_%s_new.mijauth", userID)
	os.WriteFile(newAuthFileName, []byte(newFileContent), 0644)

	fmt.Printf("✓ Wygenerowano nowy plik: %s\n", newAuthFileName)
	fmt.Println("✓ Stary plik został unieważniony\n")

	// Test starego pliku (powinien być odrzucony)
	fmt.Println("5. TEST STAREGO PLIKU (POWINIEN BYĆ ODRZUCONY)")
	fmt.Println(strings.Repeat("-", 50))

	foundUser = db.GetUser(userID) // Odśwież dane
	isOldValid := auth.VerifyAuthFileWithToken(
		string(uploadedFileContent), // Stary plik
		foundUser.EncryptionKey,
		foundUser.AuthToken, // Nowy token
		foundUser.ID,
	)

	if !isOldValid {
		fmt.Println("✓ Stary plik poprawnie odrzucony!\n")
	} else {
		fmt.Println("✗ BŁĄD: Stary plik nie powinien działać!")
	}

	// Test nowego pliku
	fmt.Println("6. TEST NOWEGO PLIKU")
	fmt.Println(strings.Repeat("-", 50))

	newUploadedContent, _ := os.ReadFile(newAuthFileName)
	isNewValid := auth.VerifyAuthFileWithToken(
		string(newUploadedContent),
		foundUser.EncryptionKey,
		foundUser.AuthToken,
		foundUser.ID,
	)

	if isNewValid {
		fmt.Println("✓ Nowy plik działa poprawnie!\n")
	} else {
		fmt.Println("✗ BŁĄD: Nowy plik powinien działać!")
	}

	// ========================================
	// Podgląd odszyfrowanej zawartości
	// ========================================
	fmt.Println("7. PODGLĄD ODSZYFROWANEJ ZAWARTOŚCI PLIKU")
	fmt.Println(strings.Repeat("-", 50))

	decryptedData, _ := auth.VerifyAuthFile(string(newUploadedContent), foundUser.EncryptionKey)
	jsonData, _ := json.MarshalIndent(decryptedData, "", "  ")
	fmt.Println("Zawartość pliku .mijauth:")
	fmt.Printf("%s\n\n", jsonData)

	// Czyszczenie
	os.Remove(authFileName)
	os.Remove(newAuthFileName)
	db.DeleteStorage()

	fmt.Println("=== DEMO ZAKOŃCZONE ===")
}

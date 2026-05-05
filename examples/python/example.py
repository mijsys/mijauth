"""
MijAuth - Przykład użycia systemu 2FA w Python
"""

import os
import json
import secrets

from mijauth import MijAuth, UserDatabase


def main():
    print("=== MijAuth - System Weryfikacji Dwuetapowej ===\n")

    # Inicjalizacja "bazy danych"
    db = UserDatabase('demo_users.json')

    # ========================================
    # KROK 1: Rejestracja użytkownika
    # ========================================
    print("1. REJESTRACJA UŻYTKOWNIKA")
    print("-" * 50)

    user_id = 'user_' + secrets.token_hex(8)
    email = 'jan.kowalski@example.com'
    password = 'bezpieczne_haslo_123'

    user, auth_file_content = db.create_user(user_id, email, password)

    print(f"✓ Utworzono użytkownika: {email}")
    print(f"✓ ID użytkownika: {user_id}")
    print("✓ Wygenerowano plik .mijauth")

    # Zapisz plik do pobrania
    auth_file_name = f"auth_{user_id}.mijauth"
    with open(auth_file_name, 'w') as f:
        f.write(auth_file_content)
    print(f"✓ Zapisano plik: {auth_file_name}\n")

    # ========================================
    # KROK 2: Logowanie - krok 1 (hasło)
    # ========================================
    print("2. LOGOWANIE - ETAP 1 (HASŁO)")
    print("-" * 50)

    login_email = 'jan.kowalski@example.com'
    login_password = 'bezpieczne_haslo_123'

    found_user = db.get_user_by_email(login_email)

    if found_user and db.verify_password(found_user, login_password):
        print("✓ Hasło poprawne!")
        print("→ Wymagana weryfikacja pliku .mijauth\n")
    else:
        print("✗ Nieprawidłowy email lub hasło")
        return

    # ========================================
    # KROK 3: Logowanie - krok 2 (plik 2FA)
    # ========================================
    print("3. LOGOWANIE - ETAP 2 (PLIK 2FA)")
    print("-" * 50)

    # Symulacja przesłania pliku przez użytkownika
    with open(auth_file_name, 'r') as f:
        uploaded_file_content = f.read()

    is_valid = MijAuth.verify_auth_file_with_token(
        uploaded_file_content,
        found_user['encryption_key'],
        found_user['auth_token'],
        found_user['id']
    )

    if is_valid:
        print("✓ Weryfikacja 2FA pomyślna!")
        print(f"✓ Użytkownik zalogowany: {found_user['email']}\n")
    else:
        print("✗ Nieprawidłowy plik autoryzacyjny")
        return

    # ========================================
    # KROK 4: Regeneracja pliku (opcjonalnie)
    # ========================================
    print("4. REGENERACJA PLIKU (UNIEWAŻNIENIE STAREGO)")
    print("-" * 50)

    new_file_content, new_token = MijAuth.regenerate_auth_file(
        user_id,
        found_user['encryption_key']
    )
    db.update_auth_token(user_id, new_token)

    new_auth_file_name = f"auth_{user_id}_new.mijauth"
    with open(new_auth_file_name, 'w') as f:
        f.write(new_file_content)

    print(f"✓ Wygenerowano nowy plik: {new_auth_file_name}")
    print("✓ Stary plik został unieważniony\n")

    # Test starego pliku (powinien być odrzucony)
    print("5. TEST STAREGO PLIKU (POWINIEN BYĆ ODRZUCONY)")
    print("-" * 50)

    found_user = db.get_user(user_id)  # Odśwież dane
    is_old_valid = MijAuth.verify_auth_file_with_token(
        uploaded_file_content,  # Stary plik
        found_user['encryption_key'],
        found_user['auth_token'],  # Nowy token
        found_user['id']
    )

    if not is_old_valid:
        print("✓ Stary plik poprawnie odrzucony!\n")
    else:
        print("✗ BŁĄD: Stary plik nie powinien działać!")

    # Test nowego pliku
    print("6. TEST NOWEGO PLIKU")
    print("-" * 50)

    with open(new_auth_file_name, 'r') as f:
        new_uploaded_content = f.read()

    is_new_valid = MijAuth.verify_auth_file_with_token(
        new_uploaded_content,
        found_user['encryption_key'],
        found_user['auth_token'],
        found_user['id']
    )

    if is_new_valid:
        print("✓ Nowy plik działa poprawnie!\n")
    else:
        print("✗ BŁĄD: Nowy plik powinien działać!")

    # ========================================
    # Podgląd odszyfrowanej zawartości
    # ========================================
    print("7. PODGLĄD ODSZYFROWANEJ ZAWARTOŚCI PLIKU")
    print("-" * 50)

    decrypted_data = MijAuth.verify_auth_file(
        new_uploaded_content,
        found_user['encryption_key']
    )
    print("Zawartość pliku .mijauth:")
    print(json.dumps(decrypted_data, indent=2) + "\n")

    # Czyszczenie
    os.remove(auth_file_name)
    os.remove(new_auth_file_name)
    db.delete_storage()

    print("=== DEMO ZAKOŃCZONE ===")


if __name__ == '__main__':
    main()

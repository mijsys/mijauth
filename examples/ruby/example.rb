#!/usr/bin/env ruby
# MijAuth - Przykład użycia systemu 2FA w Ruby

require_relative 'mijauth'
require 'securerandom'

puts "=== MijAuth - System Weryfikacji Dwuetapowej ===\n\n"

# Inicjalizacja "bazy danych"
db = MijAuth::UserDatabase.new('demo_users.json')

# ========================================
# KROK 1: Rejestracja użytkownika
# ========================================
puts "1. REJESTRACJA UŻYTKOWNIKA"
puts "-" * 50

user_id = "user_#{SecureRandom.hex(8)}"
email = 'jan.kowalski@example.com'
password = 'bezpieczne_haslo_123'

user, auth_file_content = db.create_user(user_id, email, password)

puts "✓ Utworzono użytkownika: #{email}"
puts "✓ ID użytkownika: #{user_id}"
puts "✓ Wygenerowano plik .mijauth"

# Zapisz plik do pobrania
auth_file_name = "auth_#{user_id}.mijauth"
File.write(auth_file_name, auth_file_content)
puts "✓ Zapisano plik: #{auth_file_name}\n\n"

# ========================================
# KROK 2: Logowanie - krok 1 (hasło)
# ========================================
puts "2. LOGOWANIE - ETAP 1 (HASŁO)"
puts "-" * 50

login_email = 'jan.kowalski@example.com'
login_password = 'bezpieczne_haslo_123'

found_user = db.get_user_by_email(login_email)

if found_user && db.verify_password(found_user, login_password)
  puts "✓ Hasło poprawne!"
  puts "→ Wymagana weryfikacja pliku .mijauth\n\n"
else
  puts "✗ Nieprawidłowy email lub hasło"
  exit 1
end

# ========================================
# KROK 3: Logowanie - krok 2 (plik 2FA)
# ========================================
puts "3. LOGOWANIE - ETAP 2 (PLIK 2FA)"
puts "-" * 50

# Symulacja przesłania pliku przez użytkownika
uploaded_file_content = File.read(auth_file_name)

is_valid = MijAuth::Auth.verify_auth_file_with_token(
  uploaded_file_content,
  found_user[:encryption_key],
  found_user[:auth_token],
  found_user[:id]
)

if is_valid
  puts "✓ Weryfikacja 2FA pomyślna!"
  puts "✓ Użytkownik zalogowany: #{found_user[:email]}\n\n"
else
  puts "✗ Nieprawidłowy plik autoryzacyjny"
  exit 1
end

# ========================================
# KROK 4: Regeneracja pliku (opcjonalnie)
# ========================================
puts "4. REGENERACJA PLIKU (UNIEWAŻNIENIE STAREGO)"
puts "-" * 50

new_auth_result = MijAuth::Auth.regenerate_auth_file(user_id, found_user[:encryption_key])
db.update_auth_token(user_id, new_auth_result[:token])

new_auth_file_name = "auth_#{user_id}_new.mijauth"
File.write(new_auth_file_name, new_auth_result[:file_content])

puts "✓ Wygenerowano nowy plik: #{new_auth_file_name}"
puts "✓ Stary plik został unieważniony\n\n"

# Test starego pliku (powinien być odrzucony)
puts "5. TEST STAREGO PLIKU (POWINIEN BYĆ ODRZUCONY)"
puts "-" * 50

found_user = db.get_user(user_id) # Odśwież dane
is_old_valid = MijAuth::Auth.verify_auth_file_with_token(
  uploaded_file_content, # Stary plik
  found_user[:encryption_key],
  found_user[:auth_token], # Nowy token
  found_user[:id]
)

if !is_old_valid
  puts "✓ Stary plik poprawnie odrzucony!\n\n"
else
  puts "✗ BŁĄD: Stary plik nie powinien działać!"
end

# Test nowego pliku
puts "6. TEST NOWEGO PLIKU"
puts "-" * 50

new_uploaded_content = File.read(new_auth_file_name)
is_new_valid = MijAuth::Auth.verify_auth_file_with_token(
  new_uploaded_content,
  found_user[:encryption_key],
  found_user[:auth_token],
  found_user[:id]
)

if is_new_valid
  puts "✓ Nowy plik działa poprawnie!\n\n"
else
  puts "✗ BŁĄD: Nowy plik powinien działać!"
end

# ========================================
# Podgląd odszyfrowanej zawartości
# ========================================
puts "7. PODGLĄD ODSZYFROWANEJ ZAWARTOŚCI PLIKU"
puts "-" * 50

decrypted_data = MijAuth::Auth.verify_auth_file(new_uploaded_content, found_user[:encryption_key])
puts "Zawartość pliku .mijauth:"
puts JSON.pretty_generate(decrypted_data)
puts

# Czyszczenie
File.delete(auth_file_name)
File.delete(new_auth_file_name)
db.delete_storage

puts "=== DEMO ZAKOŃCZONE ==="

# MijAuth - System Weryfikacji Dwuetapowej (2FA) oparty na plikach
# Implementacja Ruby
#
# Wymaga Ruby 3.0+ (używa wbudowanego OpenSSL)

require 'openssl'
require 'securerandom'
require 'base64'
require 'json'
require 'time'
require 'digest'

module MijAuth
  # Główna klasa systemu MijAuth do weryfikacji dwuetapowej
  class Auth
    KEY_LENGTH = 32   # 256 bits
    IV_LENGTH = 12    # 96 bits dla GCM
    TAG_LENGTH = 16   # 128 bits
    VERSION = 1

    class << self
      # Generuje nowy klucz AES-256 dla użytkownika
      # @return [String] Klucz w formacie base64
      def generate_user_key
        key = SecureRandom.random_bytes(KEY_LENGTH)
        Base64.strict_encode64(key)
      end

      # Generuje unikalny token dla użytkownika
      # @return [String] Token w formacie hex
      def generate_token
        SecureRandom.hex(32)
      end

      # Tworzy zaszyfrowany plik autoryzacyjny .mijauth
      #
      # @param user_id [String] Identyfikator użytkownika
      # @param user_key_base64 [String] Klucz użytkownika w base64
      # @param device_hash [String, nil] Opcjonalny hash urządzenia
      # @param device_hash_v2 [String, nil] Opcjonalny hash urządzenia v2
      # @return [Hash] { file_content: String, token: String }
      def create_auth_file(user_id, user_key_base64, device_hash: nil, device_hash_v2: nil)
        token = generate_token

        payload = {
          user_id: user_id,
          token: token,
          created_at: Time.now.utc.iso8601,
          device_hash: device_hash,
          device_hash_v2: device_hash_v2,
          version: VERSION
        }

        json_payload = JSON.generate(payload)
        encrypted_content = encrypt(json_payload, user_key_base64)

        { file_content: encrypted_content, token: token }
      end

      # Weryfikuje plik autoryzacyjny i zwraca dane użytkownika
      #
      # @param file_content [String] Zawartość pliku .mijauth
      # @param user_key_base64 [String] Klucz użytkownika w base64
      # @return [Hash, nil] Dane użytkownika lub nil
      def verify_auth_file(file_content, user_key_base64)
        decrypted = decrypt(file_content, user_key_base64)
        return nil if decrypted.nil?

        payload = JSON.parse(decrypted, symbolize_names: true)

        # Walidacja struktury
        return nil unless payload[:user_id] && payload[:token] && payload[:version]

        payload
      rescue JSON::ParserError, OpenSSL::Cipher::CipherError
        nil
      end

      # Weryfikuje plik i sprawdza czy token zgadza się z przechowywanym
      #
      # @param file_content [String] Zawartość pliku .mijauth
      # @param user_key_base64 [String] Klucz użytkownika w base64
      # @param expected_token [String] Oczekiwany token z bazy danych
      # @param expected_user_id [String] Oczekiwane ID użytkownika
      # @return [Boolean]
      def verify_auth_file_with_token(file_content, user_key_base64, expected_token, expected_user_id)
        payload = verify_auth_file(file_content, user_key_base64)
        return false if payload.nil?

        # Constant-time comparison
        token_match = secure_compare(expected_token, payload[:token])
        user_id_match = secure_compare(expected_user_id, payload[:user_id])

        token_match && user_id_match
      end

      # Weryfikuje plik, token i hash urządzenia (v1/v2)
      #
      # @param file_content [String]
      # @param user_key_base64 [String]
      # @param expected_token [String]
      # @param expected_user_id [String]
      # @param expected_device_hash [String, nil]
      # @param expected_device_hash_v2 [String, nil]
      # @return [Boolean]
      def verify_auth_file_with_token_and_device(
        file_content,
        user_key_base64,
        expected_token,
        expected_user_id,
        expected_device_hash: nil,
        expected_device_hash_v2: nil
      )
        payload = verify_auth_file(file_content, user_key_base64)
        return false if payload.nil?

        token_match = secure_compare(expected_token, payload[:token])
        user_id_match = secure_compare(expected_user_id, payload[:user_id])
        return false unless token_match && user_id_match

        if expected_device_hash
          return false unless payload[:device_hash]
          return false unless secure_compare(expected_device_hash, payload[:device_hash].to_s)
        end

        if expected_device_hash_v2
          return false unless payload[:device_hash_v2]
          return false unless secure_compare(expected_device_hash_v2, payload[:device_hash_v2].to_s)
        end

        true
      end

      # Regeneruje plik autoryzacyjny (nowy token)
      #
      # @param user_id [String] Identyfikator użytkownika
      # @param user_key_base64 [String] Klucz użytkownika w base64
      # @param device_hash [String, nil] Opcjonalny hash urządzenia
      # @param device_hash_v2 [String, nil] Opcjonalny hash urządzenia v2
      # @return [Hash] { file_content: String, token: String }
      def regenerate_auth_file(user_id, user_key_base64, device_hash: nil, device_hash_v2: nil)
        create_auth_file(
          user_id,
          user_key_base64,
          device_hash: device_hash,
          device_hash_v2: device_hash_v2
        )
      end

      # Generuje hash urządzenia na podstawie headers
      #
      # @param user_agent [String] User-Agent header
      # @param accept_language [String] Accept-Language header
      # @return [String] Hash urządzenia
      def generate_device_hash(user_agent: '', accept_language: '')
        data = JSON.generate({ user_agent: user_agent, accept_language: accept_language })
        Digest::SHA256.hexdigest(data)
      end

      # Generuje hash urządzenia v2 z kontekstu
      #
      # @param context [Hash]
      # @return [String]
      def generate_device_hash_v2(context = {})
        normalized = normalize_fingerprint_context(context)
        data = JSON.generate(normalized.sort.to_h)
        Digest::SHA256.hexdigest(data)
      end

      private

      # Szyfruje dane przy użyciu AES-256-GCM
      def encrypt(plaintext, key_base64)
        key = Base64.strict_decode64(key_base64)
        iv = SecureRandom.random_bytes(IV_LENGTH)

        cipher = OpenSSL::Cipher.new('aes-256-gcm')
        cipher.encrypt
        cipher.key = key
        cipher.iv = iv

        ciphertext = cipher.update(plaintext) + cipher.final
        tag = cipher.auth_tag(TAG_LENGTH)

        # Format: IV (12 bytes) + Tag (16 bytes) + Ciphertext
        combined = iv + tag + ciphertext
        Base64.strict_encode64(combined)
      end

      # Odszyfrowuje dane przy użyciu AES-256-GCM
      def decrypt(encrypted_base64, key_base64)
        key = Base64.strict_decode64(key_base64)
        combined = Base64.strict_decode64(encrypted_base64)

        return nil if combined.length < IV_LENGTH + TAG_LENGTH

        iv = combined[0, IV_LENGTH]
        tag = combined[IV_LENGTH, TAG_LENGTH]
        ciphertext = combined[(IV_LENGTH + TAG_LENGTH)..-1]

        decipher = OpenSSL::Cipher.new('aes-256-gcm')
        decipher.decrypt
        decipher.key = key
        decipher.iv = iv
        decipher.auth_tag = tag

        decipher.update(ciphertext) + decipher.final
      rescue OpenSSL::Cipher::CipherError
        nil
      end

      # Bezpieczne porównanie stringów (constant-time)
      def secure_compare(a, b)
        return false unless a.bytesize == b.bytesize

        l = a.unpack("C*")
        r = b.unpack("C*")
        res = 0
        l.zip(r) { |x, y| res |= x ^ y }
        res.zero?
      end

      def normalize_fingerprint_context(context)
        normalized = {}
        context.each do |key, value|
          next if value.nil?

          normalized[key] = value.is_a?(Hash) ? normalize_fingerprint_context(value) : value
        end

        normalized
      end
    end
  end

  # Symulacja bazy danych użytkowników
  class UserDatabase
    attr_reader :users

    def initialize(storage_file = 'users.json')
      @storage_file = storage_file
      @users = {}
      load_data
    end

    # Tworzy nowego użytkownika
    #
    # @param user_id [String] ID użytkownika
    # @param email [String] Email użytkownika
    # @param password [String] Hasło użytkownika
    # @return [Array<Hash, String>] [dane użytkownika, zawartość pliku auth]
    def create_user(user_id, email, password)
      user_key = Auth.generate_user_key
      result = Auth.create_auth_file(user_id, user_key)

      # Hash hasła (w produkcji użyj bcrypt)
      password_hash = Digest::SHA256.hexdigest(password + "salt_" + user_id)

      user = {
        id: user_id,
        email: email,
        password_hash: password_hash,
        encryption_key: user_key,
        auth_token: result[:token],
        created_at: Time.now.utc.iso8601
      }

      @users[user_id] = user
      save_data

      [user, result[:file_content]]
    end

    # Pobiera użytkownika po ID
    def get_user(user_id)
      @users[user_id]
    end

    # Pobiera użytkownika po email
    def get_user_by_email(email)
      @users.values.find { |u| u[:email] == email }
    end

    # Weryfikuje hasło użytkownika
    def verify_password(user, password)
      password_hash = Digest::SHA256.hexdigest(password + "salt_" + user[:id])
      Auth.send(:secure_compare, password_hash, user[:password_hash])
    end

    # Aktualizuje token autoryzacji
    def update_auth_token(user_id, new_token)
      if @users[user_id]
        @users[user_id][:auth_token] = new_token
        save_data
      end
    end

    # Usuwa plik storage
    def delete_storage
      File.delete(@storage_file) if File.exist?(@storage_file)
    end

    private

    def load_data
      return unless File.exist?(@storage_file)

      data = JSON.parse(File.read(@storage_file), symbolize_names: true)
      @users = data.transform_keys(&:to_s)
    rescue JSON::ParserError
      @users = {}
    end

    def save_data
      File.write(@storage_file, JSON.pretty_generate(@users))
    end
  end
end

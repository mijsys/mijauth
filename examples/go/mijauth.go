// MijAuth - System Weryfikacji Dwuetapowej (2FA) oparty na plikach
// Implementacja Go
//
// Wymaga Go 1.21+

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	KeyLength = 32 // 256 bits
	IVLength  = 12 // 96 bits dla GCM
	TagLength = 16 // 128 bits
	Version   = 1
	DefaultAuthFileTTLSeconds = 30 * 24 * 60 * 60
)

// AuthPayload struktura danych w pliku .mijauth
type AuthPayload struct {
	UserID       string  `json:"user_id"`
	Token        string  `json:"token"`
	CreatedAt    string  `json:"created_at"`
	DeviceHash   *string `json:"device_hash"`
	DeviceHashV2 *string `json:"device_hash_v2"`
	Version      int     `json:"version"`
}

// User model użytkownika
type User struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	PasswordHash  string `json:"password_hash"`
	EncryptionKey string `json:"encryption_key"`
	AuthToken     string `json:"auth_token"`
	TotpSecret    string `json:"totp_secret"`
	CreatedAt     string `json:"created_at"`
}

// MijAuth główna struktura systemu
type MijAuth struct{}

// GenerateUserKey generuje nowy klucz AES-256 dla użytkownika
func (m *MijAuth) GenerateUserKey() (string, error) {
	key := make([]byte, KeyLength)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// GenerateToken generuje unikalny token dla użytkownika
func (m *MijAuth) GenerateToken() (string, error) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	return hex.EncodeToString(token), nil
}

// CreateAuthFile tworzy zaszyfrowany plik autoryzacyjny .mijauth
func (m *MijAuth) CreateAuthFile(userID, userKeyBase64 string, deviceHash *string, deviceHashV2 *string) (string, string, error) {
	token, err := m.GenerateToken()
	if err != nil {
		return "", "", err
	}

	payload := AuthPayload{
		UserID:       userID,
		Token:        token,
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
		DeviceHash:   deviceHash,
		DeviceHashV2: deviceHashV2,
		Version:      Version,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return "", "", err
	}

	encrypted, err := m.encrypt(string(jsonPayload), userKeyBase64)
	if err != nil {
		return "", "", err
	}

	return encrypted, token, nil
}

// VerifyAuthFile weryfikuje plik autoryzacyjny i zwraca dane użytkownika
func (m *MijAuth) VerifyAuthFile(fileContent, userKeyBase64 string, maxAgeSeconds ...int) (*AuthPayload, error) {
	decrypted, err := m.decrypt(fileContent, userKeyBase64)
	if err != nil {
		return nil, err
	}

	var payload AuthPayload
	if err := json.Unmarshal([]byte(decrypted), &payload); err != nil {
		return nil, err
	}

	// Walidacja struktury
	if payload.UserID == "" || payload.Token == "" {
		return nil, fmt.Errorf("invalid payload structure")
	}

	ttl := DefaultAuthFileTTLSeconds
	if len(maxAgeSeconds) > 0 {
		ttl = maxAgeSeconds[0]
	}

	if ttl > 0 {
		createdAt, err := time.Parse(time.RFC3339, payload.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("invalid created_at")
		}

		now := time.Now().UTC()
		if createdAt.After(now) || int(now.Sub(createdAt).Seconds()) > ttl {
			return nil, fmt.Errorf("auth file expired")
		}
	}

	return &payload, nil
}

// VerifyAuthFileWithToken weryfikuje plik i sprawdza czy token zgadza się
func (m *MijAuth) VerifyAuthFileWithToken(fileContent, userKeyBase64, expectedToken, expectedUserID string, maxAgeSeconds ...int) bool {
	payload, err := m.VerifyAuthFile(fileContent, userKeyBase64, maxAgeSeconds...)
	if err != nil {
		return false
	}

	// Constant-time comparison
	tokenMatch := subtle.ConstantTimeCompare([]byte(expectedToken), []byte(payload.Token)) == 1
	userIDMatch := subtle.ConstantTimeCompare([]byte(expectedUserID), []byte(payload.UserID)) == 1

	return tokenMatch && userIDMatch
}

// GenerateTotpSecret generuje sekret TOTP Base32
func (m *MijAuth) GenerateTotpSecret(length int) (string, error) {
	if length < 16 {
		return "", fmt.Errorf("totp secret length must be at least 16")
	}

	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	var builder strings.Builder
	builder.Grow(length)
	for i := 0; i < length; i++ {
		builder.WriteByte(alphabet[int(bytes[i])%len(alphabet)])
	}

	return builder.String(), nil
}

// GetTotpProvisioningURI tworzy URI otpauth do sparowania aplikacji
func (m *MijAuth) GetTotpProvisioningURI(accountName, issuer, secret string, digits, period int) string {
	label := url.PathEscape(issuer + ":" + accountName)
	query := url.Values{}
	query.Set("secret", strings.ToUpper(secret))
	query.Set("issuer", issuer)
	query.Set("algorithm", "SHA1")
	query.Set("digits", strconv.Itoa(digits))
	query.Set("period", strconv.Itoa(period))

	return "otpauth://totp/" + label + "?" + query.Encode()
}

// GenerateTotpCode generuje kod TOTP dla podanego czasu
func (m *MijAuth) GenerateTotpCode(secret string, timestamp time.Time, period, digits int) (string, error) {
	counter := timestamp.Unix() / int64(period)
	return generateHotpCode(secret, counter, digits)
}

// VerifyTotp weryfikuje kod TOTP z tolerancją okien czasowych
func (m *MijAuth) VerifyTotp(secret, code string, discrepancy int, timestamp time.Time, period, digits int) bool {
	normalizedCode := strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(normalizedCode) != digits {
		return false
	}
	for _, ch := range normalizedCode {
		if ch < '0' || ch > '9' {
			return false
		}
	}

	baseCounter := timestamp.Unix() / int64(period)
	for offset := -discrepancy; offset <= discrepancy; offset++ {
		candidate, err := generateHotpCode(secret, baseCounter+int64(offset), digits)
		if err != nil {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(normalizedCode)) == 1 {
			return true
		}
	}

	return false
}

// VerifyAuthFileWithTokenAndDevice weryfikuje plik, token i hash urządzenia (v1/v2)
func (m *MijAuth) VerifyAuthFileWithTokenAndDevice(
	fileContent, userKeyBase64, expectedToken, expectedUserID string,
	expectedDeviceHash *string,
	expectedDeviceHashV2 *string,
) bool {
	payload, err := m.VerifyAuthFile(fileContent, userKeyBase64)
	if err != nil {
		return false
	}

	tokenMatch := subtle.ConstantTimeCompare([]byte(expectedToken), []byte(payload.Token)) == 1
	userIDMatch := subtle.ConstantTimeCompare([]byte(expectedUserID), []byte(payload.UserID)) == 1
	if !tokenMatch || !userIDMatch {
		return false
	}

	if expectedDeviceHash != nil {
		if payload.DeviceHash == nil {
			return false
		}
		deviceMatch := subtle.ConstantTimeCompare([]byte(*expectedDeviceHash), []byte(*payload.DeviceHash)) == 1
		if !deviceMatch {
			return false
		}
	}

	if expectedDeviceHashV2 != nil {
		if payload.DeviceHashV2 == nil {
			return false
		}
		deviceMatchV2 := subtle.ConstantTimeCompare([]byte(*expectedDeviceHashV2), []byte(*payload.DeviceHashV2)) == 1
		if !deviceMatchV2 {
			return false
		}
	}

	return true
}

// RegenerateAuthFile regeneruje plik autoryzacyjny (nowy token)
func (m *MijAuth) RegenerateAuthFile(userID, userKeyBase64 string, deviceHash *string, deviceHashV2 *string) (string, string, error) {
	return m.CreateAuthFile(userID, userKeyBase64, deviceHash, deviceHashV2)
}

// encrypt szyfruje dane przy użyciu AES-256-GCM
func (m *MijAuth) encrypt(plaintext, keyBase64 string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	iv := make([]byte, IVLength)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nil, iv, []byte(plaintext), nil)

	// Format: IV (12 bytes) + Ciphertext + Tag
	combined := append(iv, ciphertext...)

	return base64.StdEncoding.EncodeToString(combined), nil
}

// decrypt odszyfrowuje dane przy użyciu AES-256-GCM
func (m *MijAuth) decrypt(encryptedBase64, keyBase64 string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return "", err
	}

	combined, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return "", err
	}

	if len(combined) < IVLength+TagLength {
		return "", fmt.Errorf("ciphertext too short")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	iv := combined[:IVLength]
	ciphertext := combined[IVLength:]

	plaintext, err := aesGCM.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// GenerateDeviceHash generuje hash urządzenia
func (m *MijAuth) GenerateDeviceHash(userAgent, acceptLanguage string) string {
	data := fmt.Sprintf(`{"user_agent":"%s","accept_language":"%s"}`, userAgent, acceptLanguage)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// GenerateDeviceHashV2 generuje hash urządzenia v2 z kontekstu
func (m *MijAuth) GenerateDeviceHashV2(context map[string]interface{}) string {
	normalized := normalizeFingerprintContext(context)
	jsonString, err := encodeSortedJSON(normalized)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256([]byte(jsonString))
	return hex.EncodeToString(hash[:])
}

// UserDatabase symulacja bazy danych użytkowników
type UserDatabase struct {
	users       map[string]*User
	storageFile string
}

// NewUserDatabase tworzy nową instancję bazy danych
func NewUserDatabase(storageFile string) *UserDatabase {
	db := &UserDatabase{
		users:       make(map[string]*User),
		storageFile: storageFile,
	}
	db.load()
	return db
}

func (db *UserDatabase) load() {
	data, err := os.ReadFile(db.storageFile)
	if err != nil {
		return
	}
	json.Unmarshal(data, &db.users)
}

func (db *UserDatabase) save() error {
	data, err := json.MarshalIndent(db.users, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(db.storageFile, data, 0644)
}

// CreateUser tworzy nowego użytkownika
func (db *UserDatabase) CreateUser(userID, email, password string) (*User, string, error) {
	auth := &MijAuth{}

	userKey, err := auth.GenerateUserKey()
	if err != nil {
		return nil, "", err
	}

	fileContent, token, err := auth.CreateAuthFile(userID, userKey, nil, nil)
	if err != nil {
		return nil, "", err
	}

	totpSecret, err := auth.GenerateTotpSecret(32)
	if err != nil {
		return nil, "", err
	}

	// Hash hasła (w produkcji użyj bcrypt lub argon2)
	passwordHash := sha256.Sum256([]byte(password + "salt_" + userID))

	user := &User{
		ID:            userID,
		Email:         email,
		PasswordHash:  hex.EncodeToString(passwordHash[:]),
		EncryptionKey: userKey,
		AuthToken:     token,
		TotpSecret:    totpSecret,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}

	db.users[userID] = user
	db.save()

	return user, fileContent, nil
}

// GetUser pobiera użytkownika po ID
func (db *UserDatabase) GetUser(userID string) *User {
	return db.users[userID]
}

// GetUserByEmail pobiera użytkownika po email
func (db *UserDatabase) GetUserByEmail(email string) *User {
	for _, user := range db.users {
		if user.Email == email {
			return user
		}
	}
	return nil
}

// VerifyPassword weryfikuje hasło użytkownika
func (db *UserDatabase) VerifyPassword(user *User, password string) bool {
	passwordHash := sha256.Sum256([]byte(password + "salt_" + user.ID))
	hash := hex.EncodeToString(passwordHash[:])
	return subtle.ConstantTimeCompare([]byte(hash), []byte(user.PasswordHash)) == 1
}

// UpdateAuthToken aktualizuje token autoryzacji
func (db *UserDatabase) UpdateAuthToken(userID, newToken string) {
	if user, exists := db.users[userID]; exists {
		user.AuthToken = newToken
		db.save()
	}
}

// DeleteStorage usuwa plik storage
func (db *UserDatabase) DeleteStorage() {
	os.Remove(db.storageFile)
}

// generateRandomHex generuje losowy string hex
func generateRandomHex(n int) string {
	bytes := make([]byte, n)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func normalizeFingerprintContext(context map[string]interface{}) map[string]interface{} {
	normalized := make(map[string]interface{})
	for key, value := range context {
		if value == nil {
			continue
		}
		switch v := value.(type) {
		case map[string]interface{}:
			normalized[key] = normalizeFingerprintContext(v)
		default:
			normalized[key] = v
		}
	}
	return normalized
}

func encodeSortedJSON(value interface{}) (string, error) {
	var buffer bytes.Buffer
	if err := writeSortedJSON(&buffer, value); err != nil {
		return "", err
	}
	return buffer.String(), nil
}

func writeSortedJSON(buffer *bytes.Buffer, value interface{}) error {
	switch v := value.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		buffer.WriteString("{")
		for i, key := range keys {
			if i > 0 {
				buffer.WriteString(",")
			}
			keyJSON, err := json.Marshal(key)
			if err != nil {
				return err
			}
			buffer.Write(keyJSON)
			buffer.WriteString(":")
			if err := writeSortedJSON(buffer, v[key]); err != nil {
				return err
			}
		}
		buffer.WriteString("}")
	case []interface{}:
		buffer.WriteString("[")
		for i, item := range v {
			if i > 0 {
				buffer.WriteString(",")
			}
			if err := writeSortedJSON(buffer, item); err != nil {
				return err
			}
		}
		buffer.WriteString("]")
	case string:
		encoded, err := json.Marshal(v)
		if err != nil {
			return err
		}
		buffer.Write(encoded)
	default:
		encoded, err := json.Marshal(v)
		if err != nil {
			return err
		}
		buffer.WriteString(strings.TrimSpace(string(encoded)))
	}

	return nil
}

func generateHotpCode(secret string, counter int64, digits int) (string, error) {
	if counter < 0 {
		return strings.Repeat("0", digits), nil
	}

	decoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	key, err := decoder.DecodeString(strings.ToUpper(strings.ReplaceAll(secret, " ", "")))
	if err != nil || len(key) == 0 {
		return "", fmt.Errorf("invalid totp secret")
	}

	var ctr [8]byte
	for i := 7; i >= 0; i-- {
		ctr[i] = byte(counter & 0xff)
		counter >>= 8
	}

	h := hmac.New(sha1.New, key)
	if _, err := h.Write(ctr[:]); err != nil {
		return "", err
	}
	hash := h.Sum(nil)
	offset := hash[len(hash)-1] & 0x0f

	binary := (int(hash[offset]&0x7f) << 24) |
		(int(hash[offset+1]&0xff) << 16) |
		(int(hash[offset+2]&0xff) << 8) |
		int(hash[offset+3]&0xff)

	mod := 1
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	code := binary % mod

	return fmt.Sprintf("%0*d", digits, code), nil
}

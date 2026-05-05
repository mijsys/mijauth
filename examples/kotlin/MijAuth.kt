import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Instant
import java.time.Duration
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.max

object MijAuth {
    private const val KEY_LENGTH = 32
    private const val IV_LENGTH = 12
    private const val TAG_LENGTH_BITS = 128
    private const val VERSION = 1
    private const val DEFAULT_AUTH_FILE_TTL_SECONDS = 30L * 24L * 60L * 60L

    data class AuthPayload(
        val user_id: String,
        val token: String,
        val created_at: String,
        val device_hash: String? = null,
        val device_hash_v2: String? = null,
        val version: Int = VERSION
    )

    data class User(
        val id: String,
        val email: String,
        val password_hash: String,
        val encryption_key: String,
        var auth_token: String,
        val totp_secret: String,
        val created_at: String
    )

    fun generateUserKey(): String {
        val key = ByteArray(KEY_LENGTH)
        SecureRandom().nextBytes(key)
        return Base64.getEncoder().encodeToString(key)
    }

    fun generateToken(): String {
        val token = ByteArray(32)
        SecureRandom().nextBytes(token)
        return token.joinToString("") { "%02x".format(it) }
    }

    fun createAuthFile(
        userId: String,
        userKeyBase64: String,
        deviceHash: String? = null,
        deviceHashV2: String? = null
    ): Pair<String, String> {
        val token = generateToken()
        val payload = AuthPayload(
            user_id = userId,
            token = token,
            created_at = Instant.now().toString(),
            device_hash = deviceHash,
            device_hash_v2 = deviceHashV2
        )

        val jsonPayload = toJson(payload)
        return encrypt(jsonPayload, userKeyBase64) to token
    }

    fun verifyAuthFile(
        fileContent: String,
        userKeyBase64: String,
        maxAgeSeconds: Long? = DEFAULT_AUTH_FILE_TTL_SECONDS
    ): AuthPayload? {
        val decrypted = decrypt(fileContent, userKeyBase64) ?: return null
        val payload = parsePayload(decrypted) ?: return null

        if (payload.user_id.isBlank() || payload.token.isBlank()) return null

        if (maxAgeSeconds != null) {
            val createdAt = runCatching { Instant.parse(payload.created_at) }.getOrNull() ?: return null
            val now = Instant.now()
            if (createdAt.isAfter(now)) return null
            if (Duration.between(createdAt, now).seconds > maxAgeSeconds) return null
        }

        return payload
    }

    fun verifyAuthFileWithToken(
        fileContent: String,
        userKeyBase64: String,
        expectedToken: String,
        expectedUserId: String,
        maxAgeSeconds: Long? = DEFAULT_AUTH_FILE_TTL_SECONDS
    ): Boolean {
        val payload = verifyAuthFile(fileContent, userKeyBase64, maxAgeSeconds) ?: return false
        return fixedTimeEquals(expectedToken, payload.token) && fixedTimeEquals(expectedUserId, payload.user_id)
    }

    fun regenerateAuthFile(
        userId: String,
        userKeyBase64: String,
        deviceHash: String? = null,
        deviceHashV2: String? = null
    ): Pair<String, String> = createAuthFile(userId, userKeyBase64, deviceHash, deviceHashV2)

    fun generateTotpSecret(length: Int = 32): String {
        require(length >= 16) { "Sekret TOTP musi mieć co najmniej 16 znaków" }
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        val random = ByteArray(length)
        SecureRandom().nextBytes(random)
        return buildString(length) {
            random.forEach { append(alphabet[(it.toInt() and 0xff) % alphabet.length]) }
        }
    }

    fun getTotpProvisioningUri(
        accountName: String,
        issuer: String,
        secret: String,
        digits: Int = 6,
        period: Int = 30
    ): String {
        val label = java.net.URLEncoder.encode("$issuer:$accountName", Charsets.UTF_8)
        val query = listOf(
            "secret=${java.net.URLEncoder.encode(secret.uppercase(), Charsets.UTF_8)}",
            "issuer=${java.net.URLEncoder.encode(issuer, Charsets.UTF_8)}",
            "algorithm=SHA1",
            "digits=$digits",
            "period=$period"
        ).joinToString("&")

        return "otpauth://totp/$label?$query"
    }

    fun generateTotpCode(
        secret: String,
        timestampSeconds: Long = Instant.now().epochSecond,
        period: Int = 30,
        digits: Int = 6
    ): String {
        val counter = timestampSeconds / period
        return generateHotpCode(secret, counter, digits)
    }

    fun verifyTotp(
        secret: String,
        code: String,
        discrepancy: Int = 1,
        timestampSeconds: Long = Instant.now().epochSecond,
        period: Int = 30,
        digits: Int = 6
    ): Boolean {
        val normalizedCode = code.replace("\\s+".toRegex(), "")
        if (!normalizedCode.matches(Regex("^\\\\d{$digits}$"))) return false

        val baseCounter = timestampSeconds / period
        for (offset in -discrepancy..discrepancy) {
            val candidate = generateHotpCode(secret, baseCounter + offset, digits)
            if (fixedTimeEquals(candidate, normalizedCode)) return true
        }

        return false
    }

    private fun generateHotpCode(secret: String, counter: Long, digits: Int): String {
        if (counter < 0) return "0".repeat(digits)

        val key = decodeBase32(secret)
        require(key.isNotEmpty()) { "Nieprawidłowy sekret TOTP" }

        val counterBytes = ByteArray(8)
        var value = counter
        for (i in 7 downTo 0) {
            counterBytes[i] = (value and 0xff).toByte()
            value = value shr 8
        }

        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(key, "HmacSHA1"))
        val hash = mac.doFinal(counterBytes)
        val offset = hash.last().toInt() and 0x0f
        val binary =
            ((hash[offset].toInt() and 0x7f) shl 24) or
            ((hash[offset + 1].toInt() and 0xff) shl 16) or
            ((hash[offset + 2].toInt() and 0xff) shl 8) or
            (hash[offset + 3].toInt() and 0xff)

        val mod = Math.pow(10.0, digits.toDouble()).toInt()
        return (binary % mod).toString().padStart(digits, '0')
    }

    private fun decodeBase32(secret: String): ByteArray {
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        val normalized = secret.replace("=", "").replace("\\s+".toRegex(), "").uppercase()
        val bits = StringBuilder()

        for (ch in normalized) {
            val idx = alphabet.indexOf(ch)
            if (idx < 0) return ByteArray(0)
            bits.append(idx.toString(2).padStart(5, '0'))
        }

        val bytes = ArrayList<Byte>()
        var i = 0
        while (i + 8 <= bits.length) {
            val byteValue = bits.substring(i, i + 8).toInt(2)
            bytes.add(byteValue.toByte())
            i += 8
        }

        return bytes.toByteArray()
    }

    private fun encrypt(plaintext: String, keyBase64: String): String {
        val key = Base64.getDecoder().decode(keyBase64)
        val iv = ByteArray(IV_LENGTH)
        SecureRandom().nextBytes(iv)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcm = GCMParameterSpec(TAG_LENGTH_BITS, iv)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), gcm)
        val ciphertextWithTag = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))

        val combined = iv + ciphertextWithTag
        return Base64.getEncoder().encodeToString(combined)
    }

    private fun decrypt(encryptedBase64: String, keyBase64: String): String? {
        return try {
            val key = Base64.getDecoder().decode(keyBase64)
            val combined = Base64.getDecoder().decode(encryptedBase64)
            if (combined.size < IV_LENGTH + 16) return null

            val iv = combined.copyOfRange(0, IV_LENGTH)
            val ciphertextWithTag = combined.copyOfRange(IV_LENGTH, combined.size)

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcm = GCMParameterSpec(TAG_LENGTH_BITS, iv)
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), gcm)
            val plaintext = cipher.doFinal(ciphertextWithTag)
            plaintext.toString(Charsets.UTF_8)
        } catch (_: Exception) {
            null
        }
    }

    fun generateDeviceHash(userAgent: String = "", acceptLanguage: String = "", deviceId: String = ""): String {
        val data = "{\"user_agent\":\"$userAgent\",\"accept_language\":\"$acceptLanguage\",\"device_id\":\"$deviceId\"}"
        return sha256Hex(data)
    }

    private fun toJson(payload: AuthPayload): String {
        fun n(v: String?) = if (v == null) "null" else "\"${v.replace("\"", "\\\"")}\""
        return "{" +
            "\"user_id\":${n(payload.user_id)}," +
            "\"token\":${n(payload.token)}," +
            "\"created_at\":${n(payload.created_at)}," +
            "\"device_hash\":${n(payload.device_hash)}," +
            "\"device_hash_v2\":${n(payload.device_hash_v2)}," +
            "\"version\":${payload.version}" +
            "}"
    }

    private fun parsePayload(json: String): AuthPayload? {
        val regex = Regex("\"(user_id|token|created_at|device_hash|device_hash_v2|version)\"\\s*:\\s*(null|\"[^\"]*\"|\\d+)")
        val values = mutableMapOf<String, String?>()
        regex.findAll(json).forEach { match ->
            val key = match.groupValues[1]
            val raw = match.groupValues[2]
            values[key] = if (raw == "null") null else raw.trim('"')
        }

        val userId = values["user_id"] ?: return null
        val token = values["token"] ?: return null
        val createdAt = values["created_at"] ?: return null
        val version = values["version"]?.toIntOrNull() ?: VERSION

        return AuthPayload(
            user_id = userId,
            token = token,
            created_at = createdAt,
            device_hash = values["device_hash"],
            device_hash_v2 = values["device_hash_v2"],
            version = version
        )
    }

    private fun fixedTimeEquals(a: String, b: String): Boolean {
        val aa = a.toByteArray(Charsets.UTF_8)
        val bb = b.toByteArray(Charsets.UTF_8)
        if (aa.size != bb.size) return false

        var diff = 0
        for (i in aa.indices) diff = diff or (aa[i].toInt() xor bb[i].toInt())
        return diff == 0
    }

    private fun sha256Hex(value: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }
}

class UserDatabase(private val storageFile: String = "users.json") {
    private val users = mutableMapOf<String, MijAuth.User>()

    init {
        load()
    }

    fun createUser(userId: String, email: String, password: String): Pair<MijAuth.User, String> {
        val userKey = MijAuth.generateUserKey()
        val (authFile, token) = MijAuth.createAuthFile(userId, userKey)
        val totpSecret = MijAuth.generateTotpSecret()
        val passwordHash = sha256Hex(password + "salt_" + userId)

        val user = MijAuth.User(
            id = userId,
            email = email,
            password_hash = passwordHash,
            encryption_key = userKey,
            auth_token = token,
            totp_secret = totpSecret,
            created_at = Instant.now().toString()
        )

        users[userId] = user
        save()

        return user to authFile
    }

    fun getUser(userId: String): MijAuth.User? = users[userId]

    fun getUserByEmail(email: String): MijAuth.User? = users.values.firstOrNull { it.email == email }

    fun verifyPassword(user: MijAuth.User, password: String): Boolean {
        return sha256Hex(password + "salt_" + user.id) == user.password_hash
    }

    fun updateAuthToken(userId: String, newToken: String) {
        val existing = users[userId] ?: return
        users[userId] = existing.copy(auth_token = newToken)
        save()
    }

    fun deleteStorage() {
        File(storageFile).delete()
    }

    private fun load() {
        val file = File(storageFile)
        if (!file.exists()) return

        val text = file.readText()
        val objectRegex = Regex("\\{[^{}]*}")
        objectRegex.findAll(text).forEach { match ->
            val user = parseUser(match.value)
            if (user != null) users[user.id] = user
        }
    }

    private fun save() {
        val serialized = users.entries.joinToString(",\n", prefix = "{\n", postfix = "\n}") { (id, u) ->
            "  \"$id\": {\"id\":\"${u.id}\",\"email\":\"${u.email}\",\"password_hash\":\"${u.password_hash}\",\"encryption_key\":\"${u.encryption_key}\",\"auth_token\":\"${u.auth_token}\",\"totp_secret\":\"${u.totp_secret}\",\"created_at\":\"${u.created_at}\"}"
        }
        File(storageFile).writeText(serialized)
    }

    private fun parseUser(json: String): MijAuth.User? {
        val regex = Regex("\"(id|email|password_hash|encryption_key|auth_token|totp_secret|created_at)\"\\s*:\\s*\"([^\"]*)\"")
        val values = mutableMapOf<String, String>()
        regex.findAll(json).forEach { values[it.groupValues[1]] = it.groupValues[2] }

        val id = values["id"] ?: return null
        return MijAuth.User(
            id = id,
            email = values["email"] ?: return null,
            password_hash = values["password_hash"] ?: return null,
            encryption_key = values["encryption_key"] ?: return null,
            auth_token = values["auth_token"] ?: return null,
            totp_secret = values["totp_secret"] ?: return null,
            created_at = values["created_at"] ?: return null
        )
    }

    private fun sha256Hex(value: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }
}

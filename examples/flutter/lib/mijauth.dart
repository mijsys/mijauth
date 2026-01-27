import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:crypto/crypto.dart';

class MijAuth {
  static const String cipher = 'aes-256-gcm';
  static const int keyLength = 32;
  static const int ivLength = 12;
  static const int tagLength = 16;
  static const int version = 1;

  static const String libraryVersion = '0.3.0';

  static final AesGcm _algorithm = AesGcm.with256bits();

  static String generateUserKey() {
    final bytes = _randomBytes(keyLength);
    return base64Encode(bytes);
  }

  static String generateToken() {
    return _bytesToHex(_randomBytes(32));
  }

  static Future<Map<String, String>> createAuthFile(
    String userId,
    String userKeyBase64, {
    String? deviceHash,
    String? deviceHashV2,
  }) async {
    final token = generateToken();

    final payload = <String, dynamic>{
      'user_id': userId,
      'token': token,
      'created_at': DateTime.now().toUtc().toIso8601String(),
      'device_hash': deviceHash,
      'device_hash_v2': deviceHashV2,
      'version': version,
    };

    final jsonPayload = jsonEncode(payload);
    final encryptedContent = await encrypt(jsonPayload, userKeyBase64);

    return {
      'file_content': encryptedContent,
      'token': token,
    };
  }

  static Future<Map<String, dynamic>?> verifyAuthFile(
    String fileContent,
    String userKeyBase64,
  ) async {
    try {
      final decrypted = await decrypt(fileContent, userKeyBase64);
      if (decrypted == null) {
        return null;
      }

      final payload = jsonDecode(decrypted) as Map<String, dynamic>;

      if (!payload.containsKey('user_id') ||
          !payload.containsKey('token') ||
          !payload.containsKey('version')) {
        return null;
      }

      return payload;
    } catch (_) {
      return null;
    }
  }

  static Future<bool> verifyAuthFileWithToken(
    String fileContent,
    String userKeyBase64,
    String expectedToken,
    String expectedUserId,
  ) async {
    final payload = await verifyAuthFile(fileContent, userKeyBase64);
    if (payload == null) {
      return false;
    }

    return _timingSafeEquals(expectedToken, payload['token'] as String) &&
        _timingSafeEquals(expectedUserId, payload['user_id'] as String);
  }

  static Future<bool> verifyAuthFileWithTokenAndDevice(
    String fileContent,
    String userKeyBase64,
    String expectedToken,
    String expectedUserId, {
    String? expectedDeviceHash,
    String? expectedDeviceHashV2,
  }) async {
    final payload = await verifyAuthFile(fileContent, userKeyBase64);
    if (payload == null) {
      return false;
    }

    if (!_timingSafeEquals(expectedToken, payload['token'] as String) ||
        !_timingSafeEquals(expectedUserId, payload['user_id'] as String)) {
      return false;
    }

    if (expectedDeviceHash != null) {
      if (!payload.containsKey('device_hash') ||
          !_timingSafeEquals(expectedDeviceHash, payload['device_hash'] as String)) {
        return false;
      }
    }

    if (expectedDeviceHashV2 != null) {
      if (!payload.containsKey('device_hash_v2') ||
          !_timingSafeEquals(expectedDeviceHashV2, payload['device_hash_v2'] as String)) {
        return false;
      }
    }

    return true;
  }

  static Future<Map<String, String>> regenerateAuthFile(
    String userId,
    String userKeyBase64, {
    String? deviceHash,
    String? deviceHashV2,
  }) {
    return createAuthFile(
      userId,
      userKeyBase64,
      deviceHash: deviceHash,
      deviceHashV2: deviceHashV2,
    );
  }

  static String generateDeviceHash(
    String userAgent,
    String acceptLanguage, {
    Map<String, dynamic> additionalData = const {},
  }) {
    final data = <String, dynamic>{
      'user_agent': userAgent,
      'accept_language': acceptLanguage,
      ...additionalData,
    };

    return sha256.convert(utf8.encode(jsonEncode(data))).toString();
  }

  static String generateDeviceHashV2(Map<String, dynamic> context) {
    final normalized = _normalizeFingerprintContext(context);
    return sha256.convert(utf8.encode(jsonEncode(normalized))).toString();
  }

  static Future<String> encrypt(String plaintext, String keyBase64) async {
    final keyBytes = base64Decode(keyBase64);
    if (keyBytes.length != keyLength) {
      throw ArgumentError('Invalid encryption key');
    }

    final secretKey = SecretKey(keyBytes);
    final nonce = _randomBytes(ivLength);

    final secretBox = await _algorithm.encrypt(
      utf8.encode(plaintext),
      secretKey: secretKey,
      nonce: nonce,
    );

    final combined = Uint8List(ivLength + tagLength + secretBox.cipherText.length);
    combined.setRange(0, ivLength, secretBox.nonce);
    combined.setRange(ivLength, ivLength + tagLength, secretBox.mac.bytes);
    combined.setRange(ivLength + tagLength, combined.length, secretBox.cipherText);

    return base64Encode(combined);
  }

  static Future<String?> decrypt(String encryptedBase64, String keyBase64) async {
    final keyBytes = base64Decode(keyBase64);
    if (keyBytes.length != keyLength) {
      return null;
    }

    final combined = base64Decode(encryptedBase64);
    if (combined.length < ivLength + tagLength) {
      return null;
    }

    final nonce = combined.sublist(0, ivLength);
    final macBytes = combined.sublist(ivLength, ivLength + tagLength);
    final cipherText = combined.sublist(ivLength + tagLength);

    final secretBox = SecretBox(
      cipherText,
      nonce: nonce,
      mac: Mac(macBytes),
    );

    try {
      final clearText = await _algorithm.decrypt(
        secretBox,
        secretKey: SecretKey(keyBytes),
      );
      return utf8.decode(clearText);
    } catch (_) {
      return null;
    }
  }

  static List<int> _randomBytes(int length) {
    final random = Random.secure();
    return List<int>.generate(length, (_) => random.nextInt(256));
  }

  static String _bytesToHex(List<int> bytes) {
    final buffer = StringBuffer();
    for (final b in bytes) {
      buffer.write(b.toRadixString(16).padLeft(2, '0'));
    }
    return buffer.toString();
  }

  static bool _timingSafeEquals(String a, String b) {
    final aBytes = utf8.encode(a);
    final bBytes = utf8.encode(b);

    if (aBytes.length != bBytes.length) {
      return false;
    }

    var result = 0;
    for (var i = 0; i < aBytes.length; i++) {
      result |= aBytes[i] ^ bBytes[i];
    }
    return result == 0;
  }

  static bool timingSafeEquals(String a, String b) {
    return _timingSafeEquals(a, b);
  }

  static Map<String, dynamic> _normalizeFingerprintContext(
    Map<String, dynamic> context,
  ) {
    final normalized = <String, dynamic>{};

    for (final entry in context.entries) {
      final value = entry.value;
      if (value == null) {
        continue;
      }
      if (value is Map<String, dynamic>) {
        normalized[entry.key] = _normalizeFingerprintContext(value);
      } else {
        normalized[entry.key] = value;
      }
    }

    final sortedKeys = normalized.keys.toList()..sort();
    return {for (final key in sortedKeys) key: normalized[key]};
  }
}

class DemoUser {
  DemoUser({
    required this.id,
    required this.email,
    required this.passwordHash,
    required this.encryptionKey,
    required this.authToken,
  });

  final String id;
  final String email;
  final String passwordHash;
  final String encryptionKey;
  String authToken;
}

class DemoUserDatabase {
  final Map<String, DemoUser> _users = {};

  DemoUser? getUserByEmail(String email) {
    for (final user in _users.values) {
      if (user.email == email) {
        return user;
      }
    }
    return null;
  }

  DemoUser? getUser(String userId) {
    return _users[userId];
  }

  Future<Map<String, String>> createUser(
    String userId,
    String email,
    String password,
  ) async {
    final userKey = MijAuth.generateUserKey();
    final authResult = await MijAuth.createAuthFile(userId, userKey);

    final passwordHash = sha256
        .convert(utf8.encode(password + 'salt_' + userId))
        .toString();

    final user = DemoUser(
      id: userId,
      email: email,
      passwordHash: passwordHash,
      encryptionKey: userKey,
      authToken: authResult['token']!,
    );

    _users[userId] = user;

    return {
      'auth_file': authResult['file_content']!,
      'token': authResult['token']!,
    };
  }

  bool verifyPassword(DemoUser user, String password) {
    final hash = sha256
        .convert(utf8.encode(password + 'salt_' + user.id))
        .toString();
    return MijAuth.timingSafeEquals(hash, user.passwordHash);
  }

  void updateAuthToken(String userId, String newToken) {
    final user = _users[userId];
    if (user != null) {
      user.authToken = newToken;
    }
  }
}

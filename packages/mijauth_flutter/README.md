# mijauth_flutter

File-based 2FA (.mijauth) for Flutter/Dart.

## Install

```yaml
dependencies:
  mijauth_flutter: ^0.3.0
```

## Usage

```dart
import 'package:mijauth_flutter/mijauth.dart';

final userKey = MijAuth.generateUserKey();
final result = await MijAuth.createAuthFile('user123', userKey);

final ok = await MijAuth.verifyAuthFileWithToken(
  result['file_content']!,
  userKey,
  result['token']!,
  'user123',
);
```

## Features
- AES-256-GCM encryption
- Device fingerprint v1/v2
- Token verification with constant-time compare

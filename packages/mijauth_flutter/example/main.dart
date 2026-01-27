import 'package:mijauth_flutter/mijauth.dart';

Future<void> main() async {
  final userKey = MijAuth.generateUserKey();
  final result = await MijAuth.createAuthFile('user123', userKey);

  final ok = await MijAuth.verifyAuthFileWithToken(
    result['file_content']!,
    userKey,
    result['token']!,
    'user123',
  );

  print('Auth file valid: $ok');
}

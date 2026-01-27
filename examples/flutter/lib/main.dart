import 'package:flutter/material.dart';

import 'mijauth.dart';

void main() {
  runApp(const MijAuthDemoApp());
}

class MijAuthDemoApp extends StatelessWidget {
  const MijAuthDemoApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'MijAuth Flutter Demo',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.indigo),
        useMaterial3: true,
      ),
      home: const MijAuthDemoPage(),
    );
  }
}

class MijAuthDemoPage extends StatefulWidget {
  const MijAuthDemoPage({super.key});

  @override
  State<MijAuthDemoPage> createState() => _MijAuthDemoPageState();
}

class _MijAuthDemoPageState extends State<MijAuthDemoPage> {
  final _db = DemoUserDatabase();

  final _userIdController = TextEditingController(text: 'user123');
  final _emailController = TextEditingController(text: 'user@example.com');
  final _passwordController = TextEditingController(text: 'password');
  final _authFileController = TextEditingController();

  String _status = 'Ready';

  @override
  void dispose() {
    _userIdController.dispose();
    _emailController.dispose();
    _passwordController.dispose();
    _authFileController.dispose();
    super.dispose();
  }

  Future<void> _registerUser() async {
    final userId = _userIdController.text.trim();
    final email = _emailController.text.trim();
    final password = _passwordController.text;

    if (userId.isEmpty || email.isEmpty || password.isEmpty) {
      setState(() => _status = 'Fill all fields');
      return;
    }

    final authResult = await _db.createUser(userId, email, password);

    setState(() {
      _authFileController.text = authResult['auth_file'] ?? '';
      _status = 'User registered. Auth file generated.';
    });
  }

  Future<void> _login() async {
    final email = _emailController.text.trim();
    final password = _passwordController.text;
    final fileContent = _authFileController.text.trim();

    if (email.isEmpty || password.isEmpty || fileContent.isEmpty) {
      setState(() => _status = 'Provide email, password and auth file');
      return;
    }

    final user = _db.getUserByEmail(email);
    if (user == null) {
      setState(() => _status = 'User not found');
      return;
    }

    if (!_db.verifyPassword(user, password)) {
      setState(() => _status = 'Invalid password');
      return;
    }

    final isValid = await MijAuth.verifyAuthFileWithToken(
      fileContent,
      user.encryptionKey,
      user.authToken,
      user.id,
    );

    setState(() {
      _status = isValid ? 'Login successful' : 'Invalid auth file';
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('MijAuth Flutter Demo'),
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _buildTextField('User ID', _userIdController),
          _buildTextField('Email', _emailController),
          _buildTextField('Password', _passwordController, obscure: true),
          const SizedBox(height: 12),
          Row(
            children: [
              ElevatedButton(
                onPressed: _registerUser,
                child: const Text('Register'),
              ),
              const SizedBox(width: 12),
              ElevatedButton(
                onPressed: _login,
                child: const Text('Login'),
              ),
            ],
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _authFileController,
            maxLines: 8,
            decoration: const InputDecoration(
              labelText: 'Auth file content (.mijauth)',
              alignLabelWithHint: true,
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 16),
          Text(
            'Status: $_status',
            style: Theme.of(context).textTheme.bodyLarge,
          ),
          const SizedBox(height: 8),
          Text(
            'Library version: ${MijAuth.libraryVersion}',
            style: Theme.of(context).textTheme.bodySmall,
          ),
        ],
      ),
    );
  }

  Widget _buildTextField(
    String label,
    TextEditingController controller, {
    bool obscure = false,
  }) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: TextField(
        controller: controller,
        obscureText: obscure,
        decoration: InputDecoration(
          labelText: label,
          border: const OutlineInputBorder(),
        ),
      ),
    );
  }
}

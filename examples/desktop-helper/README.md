# MijAuth Desktop Helper (Electron)

Provides device fingerprint + signature over a local HTTP endpoint for the browser extension.

## Run

```bash
npm install
npm start
```

## Endpoints

- `GET http://127.0.0.1:7331/fingerprint`

Response:
```json
{
  "device_hash": "...",
  "signature": "...",
  "public_key": "...",
  "payload": {"platform":"..."}
}
```

## Notes
- Keypair is generated on first run and stored in user data.
- The hash is SHA-256 of a basic OS fingerprint payload.

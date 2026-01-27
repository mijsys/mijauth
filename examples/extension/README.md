# MijAuth Browser Extension

This extension stores a `.mijauth` file in extension storage and can attach device fingerprint data from the desktop helper.

## Install

### Edge
1. Open edge://extensions
2. Enable Developer mode
3. Load unpacked → select this folder

### Firefox
1. Open about:debugging#/runtime/this-firefox
2. Load Temporary Add-on → select `manifest.json`

## Usage (Page)

The page can request data using `postMessage`:

```js
window.postMessage({ type: 'MIJAUTH_REQUEST' }, '*');
window.addEventListener('message', (event) => {
  if (event.data?.type === 'MIJAUTH_RESPONSE') {
    console.log(event.data.payload);
  }
});
```

Payload fields:
- `fileContent`
- `fileName`
- `fingerprint`
- `signature`
- `publicKey`

To enable fingerprints, run the desktop helper and click "Fetch Fingerprint" in the popup.

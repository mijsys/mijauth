# MijAuth PWA Demo

This demo shows how to use the File System Access API to pick and read a `.mijauth` file in a PWA.

## Run

Serve this folder with any static server (HTTPS or localhost):

```bash
npx serve .
```

## Notes
- File System Access works in Chromium-based browsers.
- Other browsers can use the file input fallback.
- The file handle can be remembered in IndexedDB for faster access.

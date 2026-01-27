const statusEl = document.getElementById('status');
const fsStatusEl = document.getElementById('fsStatus');
const fileContentEl = document.getElementById('fileContent');
const fileInput = document.getElementById('fileInput');

const pickFileBtn = document.getElementById('pickFile');
const readFileBtn = document.getElementById('readFile');
const saveHandleBtn = document.getElementById('saveHandle');
const forgetHandleBtn = document.getElementById('forgetHandle');

const DB_NAME = 'mijauth-pwa';
const STORE_NAME = 'handles';

const supportsFSAccess = 'showOpenFilePicker' in window;
fsStatusEl.textContent = supportsFSAccess ? 'Supported' : 'Not supported';
readFileBtn.disabled = !supportsFSAccess;
saveHandleBtn.disabled = !supportsFSAccess;
forgetHandleBtn.disabled = !supportsFSAccess;

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('sw.js');
}

let fileHandle = null;

function setStatus(text) {
  statusEl.textContent = text;
}

async function pickFile() {
  if (!supportsFSAccess) {
    setStatus('File picker not supported, use file input.');
    return;
  }

  try {
    const [handle] = await window.showOpenFilePicker({
      multiple: false,
      types: [{
        description: 'MijAuth file',
        accept: { 'application/octet-stream': ['.mijauth'] }
      }]
    });
    fileHandle = handle;
    setStatus('File handle selected.');
  } catch (err) {
    setStatus('Picker cancelled or failed.');
  }
}

async function readFileFromHandle() {
  if (!fileHandle) {
    setStatus('No handle selected.');
    return;
  }
  try {
    const file = await fileHandle.getFile();
    const content = await file.text();
    fileContentEl.value = content;
    setStatus('File read successfully.');
  } catch (err) {
    setStatus('Failed to read file.');
  }
}

function openDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function saveHandle() {
  if (!fileHandle) {
    setStatus('No handle to remember.');
    return;
  }
  try {
    const db = await openDb();
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).put(fileHandle, 'mijauth');
    await new Promise((resolve, reject) => {
      tx.oncomplete = resolve;
      tx.onerror = () => reject(tx.error);
    });
    setStatus('Handle remembered.');
  } catch (err) {
    setStatus('Failed to remember handle.');
  }
}

async function loadRememberedHandle() {
  try {
    const db = await openDb();
    const tx = db.transaction(STORE_NAME, 'readonly');
    const request = tx.objectStore(STORE_NAME).get('mijauth');
    const handle = await new Promise((resolve, reject) => {
      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => reject(request.error);
    });
    if (handle) {
      fileHandle = handle;
      setStatus('Handle loaded from storage.');
    }
  } catch (err) {
    setStatus('No stored handle.');
  }
}

async function forgetHandle() {
  fileHandle = null;
  try {
    const db = await openDb();
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).delete('mijauth');
    await new Promise((resolve, reject) => {
      tx.oncomplete = resolve;
      tx.onerror = () => reject(tx.error);
    });
  } catch (err) {
    // ignore
  }
  setStatus('Handle forgotten.');
}

fileInput.addEventListener('change', async (event) => {
  const file = event.target.files[0];
  if (!file) return;
  const content = await file.text();
  fileContentEl.value = content;
  setStatus('File loaded via input.');
});

pickFileBtn.addEventListener('click', pickFile);
readFileBtn.addEventListener('click', readFileFromHandle);
saveHandleBtn.addEventListener('click', saveHandle);
forgetHandleBtn.addEventListener('click', forgetHandle);

loadRememberedHandle();

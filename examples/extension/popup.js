const api = typeof browser !== 'undefined' ? browser : chrome;

const statusEl = document.getElementById('status');
const detailsEl = document.getElementById('details');
const fileInput = document.getElementById('fileInput');

const saveBtn = document.getElementById('saveBtn');
const fingerprintBtn = document.getElementById('fingerprintBtn');

function setStatus(text) {
  statusEl.textContent = text;
}

saveBtn.addEventListener('click', async () => {
  const file = fileInput.files[0];
  if (!file) {
    setStatus('Select a file first');
    return;
  }

  const content = await file.text();
  const response = await api.runtime.sendMessage({
    type: 'MIJAUTH_SAVE_FILE',
    fileContent: content,
    fileName: file.name
  });

  if (response?.ok) {
    setStatus('Saved');
    detailsEl.textContent = `File: ${file.name}`;
  } else {
    setStatus('Failed to save');
  }
});

fingerprintBtn.addEventListener('click', async () => {
  try {
    const response = await fetch('http://127.0.0.1:7331/fingerprint');
    if (!response.ok) {
      setStatus('Helper not available');
      return;
    }
    const data = await response.json();

    const saved = await api.runtime.sendMessage({
      type: 'MIJAUTH_SET_FINGERPRINT',
      fingerprint: data.device_hash,
      signature: data.signature,
      publicKey: data.public_key
    });

    if (saved?.ok) {
      setStatus('Fingerprint saved');
      detailsEl.textContent = `Fingerprint: ${data.device_hash.slice(0, 12)}...`;
    }
  } catch (err) {
    setStatus('Helper not running');
  }
});

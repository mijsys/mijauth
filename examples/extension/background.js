const api = typeof browser !== 'undefined' ? browser : chrome;

const DEFAULT_STATE = {
  fileContent: null,
  fileName: null,
  fingerprint: null,
  signature: null,
  publicKey: null,
  updatedAt: null
};

try {
  api.storage.local.get(DEFAULT_STATE);
} catch (err) {
  // ignore
}

async function updateState(partial) {
  await api.storage.local.set({
    ...partial,
    updatedAt: new Date().toISOString()
  });
}

api.runtime.onMessage.addListener(async (message) => {
  if (message?.type === 'MIJAUTH_SAVE_FILE') {
    await updateState({
      fileContent: message.fileContent,
      fileName: message.fileName
    });
    return { ok: true };
  }

  if (message?.type === 'MIJAUTH_SET_FINGERPRINT') {
    await updateState({
      fingerprint: message.fingerprint,
      signature: message.signature,
      publicKey: message.publicKey
    });
    return { ok: true };
  }

  if (message?.type === 'MIJAUTH_GET_STATE') {
    const state = await api.storage.local.get(DEFAULT_STATE);
    return { ok: true, state };
  }

  return { ok: false };
});

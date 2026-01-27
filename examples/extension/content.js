const api = typeof browser !== 'undefined' ? browser : chrome;

window.addEventListener('message', async (event) => {
  if (event.source !== window) return;
  if (!event.data || event.data.type !== 'MIJAUTH_REQUEST') return;

  const response = await api.runtime.sendMessage({ type: 'MIJAUTH_GET_STATE' });
  if (!response?.ok) return;

  window.postMessage({
    type: 'MIJAUTH_RESPONSE',
    payload: response.state
  }, '*');
});

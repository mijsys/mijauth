const { app, BrowserWindow, Tray, Menu } = require('electron');
const http = require('http');
const os = require('os');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const PORT = 7331;
let tray = null;

function getAppDataPath() {
  return app.getPath('userData');
}

function getKeyPaths() {
  const dir = path.join(getAppDataPath(), 'keys');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return {
    privateKey: path.join(dir, 'device_private.pem'),
    publicKey: path.join(dir, 'device_public.pem')
  };
}

function ensureKeypair() {
  const { privateKey, publicKey } = getKeyPaths();
  if (fs.existsSync(privateKey) && fs.existsSync(publicKey)) {
    return {
      privateKey: fs.readFileSync(privateKey, 'utf8'),
      publicKey: fs.readFileSync(publicKey, 'utf8')
    };
  }

  const { publicKey: pub, privateKey: priv } = crypto.generateKeyPairSync('ed25519');
  const privPem = priv.export({ format: 'pem', type: 'pkcs8' });
  const pubPem = pub.export({ format: 'pem', type: 'spki' });

  fs.writeFileSync(privateKey, privPem);
  fs.writeFileSync(publicKey, pubPem);

  return { privateKey: privPem, publicKey: pubPem };
}

function getDeviceFingerprint() {
  const net = os.networkInterfaces();
  const mac = Object.values(net)
    .flat()
    .find((item) => item && !item.internal && item.mac && item.mac !== '00:00:00:00:00:00')?.mac;

  const payload = {
    platform: os.platform(),
    release: os.release(),
    arch: os.arch(),
    hostname: os.hostname(),
    cpu: os.cpus()?.[0]?.model || '',
    mem: os.totalmem(),
    mac: mac || ''
  };

  const serialized = JSON.stringify(payload);
  const hash = crypto.createHash('sha256').update(serialized).digest('hex');
  return { hash, payload };
}

function signFingerprint(hash) {
  const { privateKey, publicKey } = ensureKeypair();
  const signature = crypto.sign(null, Buffer.from(hash, 'utf8'), privateKey).toString('base64');
  return { signature, publicKey };
}

function startServer() {
  const server = http.createServer((req, res) => {
    if (req.method === 'GET' && req.url === '/fingerprint') {
      const { hash, payload } = getDeviceFingerprint();
      const { signature, publicKey } = signFingerprint(hash);

      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      });
      res.end(JSON.stringify({
        device_hash: hash,
        signature,
        public_key: publicKey,
        payload
      }));
      return;
    }

    if (req.method === 'GET' && req.url === '/status') {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      res.end(JSON.stringify({ ok: true }));
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify({ error: 'Not found' }));
  });

  server.listen(PORT, '127.0.0.1');
}

function createWindow() {
  const win = new BrowserWindow({
    width: 420,
    height: 280,
    resizable: false,
    webPreferences: {
      contextIsolation: true
    }
  });
  win.loadFile(path.join(__dirname, 'ui.html'));
}

function createTray() {
  const iconPath = path.join(__dirname, 'tray.png');
  if (!fs.existsSync(iconPath)) {
    return;
  }
  tray = new Tray(iconPath);
  const menu = Menu.buildFromTemplate([
    { label: 'Open', click: createWindow },
    { label: 'Quit', click: () => app.quit() }
  ]);
  tray.setToolTip('MijAuth Helper');
  tray.setContextMenu(menu);
}

app.whenReady().then(() => {
  startServer();
  createTray();
  createWindow();
});

app.on('window-all-closed', (event) => {
  event.preventDefault();
});

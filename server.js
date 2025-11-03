// server.js
// Node 18+ recommended
const express = require('express');
const axios = require('axios');
const morgan = require('morgan');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const { URL } = require('url');

const app = express();
app.use(morgan('tiny'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// CONFIG: set ENCRYPTION_KEY env var to a 32-byte key (hex or base64).
// e.g. export ENCRYPTION_KEY="$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")"
const RAW_KEY = "c27165c50236de431b5a2290171b18353fafc325d0a6bcd14cd03d1b822ad912";
if (!RAW_KEY) {
  console.error('ERROR: set ENCRYPTION_KEY env variable (32 bytes hex or base64).');
  process.exit(1);
}
let ENCKEY;
if (/^[0-9a-fA-F]{64}$/.test(RAW_KEY)) {
  ENCKEY = Buffer.from(RAW_KEY, 'hex');
} else {
  ENCKEY = Buffer.from(RAW_KEY, 'base64');
}
if (ENCKEY.length !== 32) {
  console.error('ERROR: ENCRYPTION_KEY must decode to 32 bytes (256-bit).');
  process.exit(1);
}

/* ---------- Encryption helpers (AES-256-GCM, token = base64url(iv|ciphertext|tag)) ---------- */
function base64urlEncode(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function base64urlDecode(str) {
  // pad
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64');
}

function encryptText(plain) {
  const iv = crypto.randomBytes(12); // GCM recommended 12 bytes
  const cipher = crypto.createCipheriv('aes-256-gcm', ENCKEY, iv);
  const ciphertext = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  // token = base64url(iv|cipher|tag)
  return base64urlEncode(Buffer.concat([iv, ciphertext, tag]));
}

function decryptText(token) {
  const raw = base64urlDecode(token);
  if (raw.length < 12 + 16) throw new Error('Invalid token');
  const iv = raw.slice(0, 12);
  const tag = raw.slice(raw.length - 16);
  const ciphertext = raw.slice(12, raw.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', ENCKEY, iv);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plain.toString('utf8');
}

/* ---------- Utility: resolve relative URL against base ---------- */
function resolveUrl(base, maybeRel) {
  try {
    return new URL(maybeRel, base).toString();
  } catch (e) {
    return maybeRel; // fallback
  }
}

/* ---------- VK API request - uses sample headers/body you provided ---------- */
/*
 Note: For real use, move cookies and other sensitive headers into ENV or config.
*/
const VK_API_URL = 'https://api.vkvideo.ru/method/catalog.getVideo?v=5.265&client_id=52461373';
const DEFAULT_VK_COOKIES = `remixrefkey=7b3e75728e7abdb9ca; remixscreen_width=1920; remixscreen_height=1080; remixscreen_dpr=1; remixscreen_depth=24; remixdark_color_scheme=1; remixcolor_scheme_mode=auto; remixdt=9000; remixstid=228649741_xI6k7gYDtaBxveuoc0gBj1NespCpT1wl4Tf8A4TkOHs; remixlang=3; tmr_lvid=ac803a5b03f008a30b4c93a224cdc203; tmr_lvidTS=1742826759925; remixvideo_menu_collapsed=0; prcl=1ac4275b918a13; _ignoreAutoLogin=1; remixscreen_orient=1; remixsf=1; remixstlid=9069202440385892893_WJQv8kTkuXYLoAs2MykQRC2nw6UQTlFbuUYQD8OiJZw; remixgp=2923d7387899feedabc7693ab2a3907f; remixcurr_audio=null; remixmaudio=null; adblock=1; remixua=43%7C-1%7C208%7C2216461059; remixscreen_winzoom=1.50; remixsts=%7B%22data%22%3A%5B%5B1762142827%2C%22web_dark_theme%22%2C%22auto%22%2C%22vkcom_dark%22%2C1%5D%2C%5B1762142827%2C%22browser_features%22%2C%22current_scheme%3A2/is_auto_schemes_supported%3A1/is_schemes_supported%3A1%22%5D%2C%5B1762142827%2C%22counters_check%22%2C1%5D%2C%5B1762142829%2C%22web_stats_request_error%22%2C1%2C%22https%3A//stats.vk-portal.net/web-stats/p%22%2Ctrue%2C0%5D%5D%2C%22uniqueId%22%3A585557539.4820567%7D`;

// Example form data body you gave; modify owner_id/url/access_token as needed.
const DEFAULT_FORM = {
  need_blocks: '1',
  owner_id: '0',
  url: 'https://vkvideo.ru/@club233604729/lives',
  access_token: 'anonym.eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhbm9ueW1faWQiOjIwOTY0NDI2NjksImFwcF9pZCI6NTI0NjEzNzMsImlhdCI6MTc2MjE0MjgzMCwiaXNfdmVyaWZpZWQiOmZhbHNlLCJleHAiOjE3NjIyMjkyMzAsInNpZ25lZF90aW1lIjpudWxsLCJhbm9ueW1faWRfbG9uZyI6OTA2OTIwMjQ0MDM4NTg5Mjg5Mywic2NvcGUiOjc4ODEyOTkzNDc4OTgzNjh9.zldVTn9VHQGIUf0hOk-ytbpGhnrRDoiDZd987dLX1bI'
};

async function fetchVkCatalog(form = DEFAULT_FORM, cookieString = DEFAULT_VK_COOKIES) {
  const headers = {
    accept: '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'content-type': 'application/x-www-form-urlencoded',
    cookie: cookieString,
    origin: 'https://vkvideo.ru',
    referer: 'https://vkvideo.ru/',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-site',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0'
  };

  const formParams = new URLSearchParams(form).toString();
  const resp = await axios.post(VK_API_URL, formParams, { headers, timeout: 15000 });
  return resp.data;
}

/* ---------- Endpoint: fetch VK and redirect to encrypted goat ---------- */
app.get('/cursed/stream.m3u8', async (req, res) => {
  try {
    // optional: accept owner/url/access_token/cookies via query/body for flexibility
    const form = { ...DEFAULT_FORM };
    if (req.query.url) form.url = req.query.url;
    if (req.query.owner_id) form.owner_id = req.query.owner_id;
    if (req.query.access_token) form.access_token = req.query.access_token;

    const cookies = req.query.cookies || DEFAULT_VK_COOKIES;
    const vkData = await fetchVkCatalog(form, cookies);

    if (!vkData || !vkData.response || !vkData.response.videos || vkData.response.videos.length === 0) {
      return res.status(500).json({ error: 'No videos found in VK response', raw: vkData });
    }

    // Get first video object's files.hls_live
    const firstVideo = vkData.response.videos[0];
    const hls = firstVideo && firstVideo.files && firstVideo.files.hls_live;
    if (!hls) return res.status(500).json({ error: 'hls_live not available on first video', video: firstVideo });

    // Create encrypted token and redirect to /goat/:token
    const token = encryptText(hls);
    const proxiedUrl = `${req.protocol}://${req.get('host')}/goat/${token}`;
    return res.redirect(proxiedUrl);
  } catch (err) {
    console.error(err && err.stack || err);
    res.status(500).json({ error: err.message });
  }
});

/* ---------- Endpoint: Accept arbitrary external URL and return encrypted proxy location ---------- */
/*
  Usage: GET /cursed/external?url=<encodeURIComponent(url)>
  It will return the proxied token link (not the raw URL).
*/
app.get('/cursed/external', (req, res) => {
  const rawUrl = req.query.url;
  if (!rawUrl) return res.status(400).json({ error: 'url query param required' });
  try {
    // optionally validate URL
    new URL(rawUrl);
    const token = encryptText(rawUrl);
    const proxiedUrl = `${req.protocol}://${req.get('host')}/goat/${token}`;
    res.json({ proxy: proxiedUrl });
  } catch (e) {
    res.status(400).json({ error: 'Invalid URL' });
  }
});

/* ---------- Core Proxy endpoint: decrypt token, fetch resource, stream or rewrite playlist ---------- */
app.get('/goat/:token', async (req, res) => {
  const { token } = req.params;
  let decodedUrl;
  try {
    decodedUrl = decryptText(token);
  } catch (e) {
    return res.status(400).send('Invalid token');
  }

  // If it's an m3u8 playlist (playlist or nested), fetch it as text, rewrite URLs to encrypted tokens, and return text
  try {
    // make request as stream or text depending on content-type
    const response = await axios.get(decodedUrl, {
      responseType: 'arraybuffer', // we'll inspect content-type
      headers: {
        'User-Agent': req.headers['user-agent'] || 'Mozilla/5.0',
        'Accept': '*/*',
        'Referer': decodedUrl, // some servers require referer
        // add more headers if needed
      },
      maxRedirects: 5,
      validateStatus: status => status >= 200 && status < 400,
      timeout: 20000
    });

    const contentType = (response.headers['content-type'] || '').toLowerCase();
    const bodyBuf = Buffer.from(response.data);

    // If playlist (m3u8), rewrite segments and nested m3u8 links
    if (contentType.includes('mpegurl') || contentType.includes('application/vnd.apple.mpegurl') || decodedUrl.endsWith('.m3u8')) {
      const originalText = bodyBuf.toString('utf8');
      const base = decodedUrl.substring(0, decodedUrl.lastIndexOf('/') + 1);

      // Replace every non-comment line that looks like a URL or path (ts, m3u8)
      const rewritten = originalText.replace(/^(?!#)(.+)$/gm, (match) => {
        const absolute = resolveUrl(base, match.trim());
        const tokenForItem = encryptText(absolute);
        return `${req.protocol}://${req.get('host')}/goat/${tokenForItem}`;
      });

      res.setHeader('content-type', 'application/vnd.apple.mpegurl; charset=utf-8');
      return res.send(rewritten);
    }

    // For TS or binary segments or other content: stream the bytes through
    // Use content-type from original response
    res.setHeader('content-type', response.headers['content-type'] || 'application/octet-stream');
    // copy through relevant headers (cache control etc.)
    if (response.headers['content-length']) res.setHeader('content-length', response.headers['content-length']);
    if (response.headers['cache-control']) res.setHeader('cache-control', response.headers['cache-control']);

    return res.send(bodyBuf);
  } catch (err) {
    console.error('goat error:', err.message || err);
    if (err.response && err.response.status) {
      return res.status(err.response.status).send(err.response.statusText || 'Upstream error');
    }
    res.status(500).send('Proxy error');
  }
});

/* ---------- Optional simple health and info endpoints ---------- */
app.get('/', (req, res) => {
  res.send(`
    <h3>CURSED STREAM</h3>
    <ul>
      <li>CURSED TECHNIQUE</li>
      <li>INFINITE TSUKOYOMI</li>
      <li>A PROGRAM BY TRUESHIKARI</li>
    </ul>
  `);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Listening on ${PORT}`);
});

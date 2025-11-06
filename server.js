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
const DEFAULT_VK_COOKIES = `remixrefkey=7b3e75728e7abdb9ca; remixscreen_width=1920; remixscreen_height=1080; remixscreen_dpr=1; remixscreen_depth=24; remixdark_color_scheme=1; remixcolor_scheme_mode=auto; remixdt=9000; remixstid=228649741_xI6k7gYDtaBxveuoc0gBj1NespCpT1wl4Tf8A4TkOHs; remixlang=3; tmr_lvid=ac803a5b03f008a30b4c93a224cdc203; tmr_lvidTS=1742826759925; remixvideo_menu_collapsed=0; prcl=1ac4275b918a13; _ignoreAutoLogin=1; remixscreen_orient=1; remixsf=1; remixstlid=9069202440385892893_WJQv8kTkuXYLoAs2MykQRC2nw6UQTlFbuUYQD8OiJZw; remixgp=2923d7387899feedabc7693ab2a3907f; remixcurr_audio=null; remixmaudio=null; adblock=1; remixua=43%7C-1%7C208%7C2216461059; remixscreen_winzoom=1.50; remixsts=%7B%22data%22%3A%5B%5B1762142827%2C%22web_dark_theme%22%2C%22auto%22%2C%22vkcom_dark%22%2C1%5D%2C%5B1762142827%2C%22browser_features%22%2C%22current_scheme%3A2/is_auto_schemes_supported%3A1/is_schemes_supported%3A1%22%5D%2C%5B1762142827%2C%22counters_check%22%2C1%5D%2C%5B1762142829%2C%22web_stats_request_error%22%2C1%2C%22http%3A//stats.vk-portal.net/web-stats/p%22%2Ctrue%2C0%5D%5D%2C%22uniqueId%22%3A585557539.4820567%7D`;

// Example form data body you gave; modify owner_id/url/access_token as needed.
const DEFAULT_FORM = {
  need_blocks: '1',
  owner_id: '0',
  url: 'https://vkvideo.ru/@club233604729/lives',
  access_token: 'anonym.eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhbm9ueW1faWQiOjExOTg0NDk4MDcsImFwcF9pZCI6NTI2NDk4OTYsImlhdCI6MTc2MjQwMTIzMCwiaXNfdmVyaWZpZWQiOmZhbHNlLCJleHAiOjE3NjI0ODc2MzAsInNpZ25lZF90aW1lIjpudWxsLCJhbm9ueW1faWRfbG9uZyI6OTA4MjU3MjQ0ODMwODA0NjYwOSwic2NvcGUiOjc4ODEyOTkzNDc4OTgzNjh9.l1U91KYOr5kNgn1eTDIKdNdwyn7PPM6dGDy8kzgTGx8'
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

/* ---------- VK Anonymous Token Fetcher ---------- */
async function getVkAnonymousToken() {
  const url = 'https://login.vk.com/?act=get_anonym_token';
  const headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:142.0) Gecko/20100101 Firefox/142.0',
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br, zstd',
    'Referer': 'https://vkvideo.ru/',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Origin': 'https://vkvideo.ru',
    'Connection': 'keep-alive',
    'Cookie': 'remixlang=3; remixstlid=9050906657857049535_RJ6FcsXKZozNudTBYLbpDRwmKv3REalbdnISYOl8pe0; prcl=c88a224cf1c0b1',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'cross-site',
    'Priority': 'u=4',
  };

  const body = nonymous',
    isApiOauthAnonymEnabled: 'false',
    version: '1',
    app_id: '6287487',
    access_token:
      'anonym.eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhbm9ueW1faWQiOjExOTg0NDk4MDcsImFwcF9pZCI6NTI2NDk4OTYsImlhdCI6MTc2MjQwMTIzMCwiaXNfdmVyaWZpZWQiOmZhbHNlLCJleHAiOjE3NjI0ODc2MzAsInNpZ25lZF90aW1lIjpudWxsLCJhbm9ueW1faWRfbG9uZyI6OTA4MjU3MjQ0ODMwODA0NjYwOSwic2NvcGUiOjc4ODEyOTkzNDc4OTgzNjh9.l1U91KYOr5kNgn1eTDIKdNdwyn7PPM6dGDy8kzgTGx8',
  }).toString();

  const resp = await axios.post(url, body, { headers, timeout: 15000 });
  return resp.data;
}


/* ---------- Endpoint: fetch VK and redirect to encrypted goat ---------- */
app.get('/cursed/stream.m3u8', async (req, res) => {
  try {
    // Optional query overrides
    const form = { ...DEFAULT_FORM };

    // Fetch fresh anonymous token
    try {
      const tokenData = "anonym.eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhbm9ueW1faWQiOjExOTg0NDk4MDcsImFwcF9pZCI6NTI2NDk4OTYsImlhdCI6MTc2MjQwMTIzMCwiaXNfdmVyaWZpZWQiOmZhbHNlLCJleHAiOjE3NjI0ODc2MzAsInNpZ25lZF90aW1lIjpudWxsLCJhbm9ueW1faWRfbG9uZyI6OTA4MjU3MjQ0ODMwODA0NjYwOSwic2NvcGUiOjc4ODEyOTkzNDc4OTgzNjh9.l1U91KYOr5kNgn1eTDIKdNdwyn7PPM6dGDy8kzgTGx8";
      if (tokenData?.access_token) {
        form.access_token = tokenData.access_token;
      }
    } catch (err) {
      console.error('⚠️ Failed to fetch VK anon token:', err.message);
    }

    // Allow manual override via query params (optional)
    if (req.query.url) form.url = req.query.url;
    if (req.query.owner_id) form.owner_id = req.query.owner_id;
    if (req.query.access_token) form.access_token = req.query.access_token;


    const cookies = req.query.cookies || DEFAULT_VK_COOKIES;
    const vkData = await fetchVkCatalog(form, cookies);

    if (
      !vkData ||
      !vkData.response ||
      !vkData.response.videos ||
      vkData.response.videos.length === 0
    ) {
      return res.status(500).json({ error: 'No videos found in VK response', raw: vkData });
    }

    const firstVideo = vkData.response.videos[0];
    const hls = firstVideo?.files?.hls_live_ondemand;
    if (!hls) return res.status(500).json({ error: 'hls_live not available' });
    console.log(hls);
    // Fetch actual playlist from the source
    const response = await axios.get(hls, {
      responseType: 'text',
      headers: {
        'User-Agent': req.headers['user-agent'] || 'Mozilla/5.0',
        'Accept': '*/*',
        'Referer': hls,
      },
      timeout: 15000,
    });

    const base = hls.substring(0, hls.lastIndexOf('/') + 1);
    const originalText = response.data;

    // Rewrite internal links → /goat/<enc> (keep .m3u8/.ts suffix)
    const rewritten = originalText.replace(/^(?!#)(.+)$/gm, (line) => {
      const absolute = resolveUrl(base, line.trim());
      const enc = encryptText(absolute);
      let suffix = '';
      if (absolute.endsWith('.m3u8')) suffix = '.m3u8';
      else if (absolute.endsWith('.ts')) suffix = '.ts';
      return `http://${req.get('host')}/goat/${enc}${suffix}`;
    });

    res.setHeader('Content-Type', 'application/vnd.apple.mpegurl; charset=utf-8');
    res.send(rewritten);
  } catch (err) {
    console.error(err.stack || err);
    res.status(500).json({ error1: err.message });
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
/* ---------- Core Proxy endpoint (fixed for .m3u8/.ts appearance) ---------- */
app.get(/^\/goat\/(.+)$/, async (req, res) => {
  let token = req.params[0];
  let decodedUrl;

  try {
    // 🧩 Remove cosmetic .m3u8 or .ts suffix before decrypting
    // (we only strip at the very end)
    token = token.replace(/\.(m3u8|ts)$/i, '');

    decodedUrl = decryptText(token);
  } catch (e) {
    console.error('Decryption failed:', e.message);
    return res.status(400).send('Invalid token');
  }

  try {
    const response = await axios.get(decodedUrl, {
      responseType: 'arraybuffer',
      headers: {
        'User-Agent': req.headers['user-agent'] || 'Mozilla/5.0',
        'Accept': '*/*',
        'Referer': decodedUrl,
      },
      maxRedirects: 5,
      validateStatus: s => s >= 200 && s < 400,
      timeout: 20000,
    });

    const contentType = (response.headers['content-type'] || '').toLowerCase();
    const bodyBuf = Buffer.from(response.data);

    // 🎵 Handle playlists
    if (
      contentType.includes('mpegurl') ||
      contentType.includes('application/vnd.apple.mpegurl') ||
      decodedUrl.endsWith('.m3u8')
    ) {
      const originalText = bodyBuf.toString('utf8');
      const base = decodedUrl.substring(0, decodedUrl.lastIndexOf('/') + 1);

      const rewritten = originalText.replace(/^(?!#)(.+)$/gm, (line) => {
        const absolute = resolveUrl(base, line.trim());
        const enc = encryptText(absolute);

        // Add visual suffix for clarity
        let suffix = '';
        if (absolute.endsWith('.m3u8')) suffix = '.m3u8';
        else if (absolute.endsWith('.ts')) suffix = '.ts';

        return `${req.protocol}://${req.get('host')}/goat/${enc}${suffix}`;
      });

      res.setHeader('content-type', 'application/vnd.apple.mpegurl; charset=utf-8');
      return res.send(rewritten);
    }

    // 🔁 Binary pass-through (TS, etc.)
    res.setHeader('content-type', response.headers['content-type'] || 'application/octet-stream');
    if (response.headers['content-length']) res.setHeader('content-length', response.headers['content-length']);
    if (response.headers['cache-control']) res.setHeader('cache-control', response.headers['cache-control']);

    return res.send(bodyBuf);
  } catch (err) {
    console.error('Proxy error:', err.message);
    if (err.response && err.response.status) {
      return res.status(err.response.status).send(err.response.statusText || 'Upstream error');
    }
    return res.status(500).send('Proxy error');
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




/* TyraChat relay · Cloudflare Worker

   Rutas:
     POST /webhook                    → URL que se pone en la app de Kick (Habilitar webhooks)
     GET  /ws?channel=<slug>          → WebSocket al que se conecta TyraChat
     GET  /config                     → qué tiene configurado este relay (lo lee la página)
     GET  /auth/<plataforma>/start    → inicio de sesión con un clic (twitch, kick, youtube)
     GET  /auth/<plataforma>/callback
     POST /auth/<plataforma>/refresh  → renovar la sesión sin volver a conectar
     GET  /yt/api/...  /yt/live       → lectura de YouTube con la API key del relay
     GET  /kick/emotes/<slug>         → emotes del canal de Kick
     GET  /                           → comprobación rápida ("TyraChat relay OK")
*/
import { DurableObject } from 'cloudflare:workers';
const VERSION = '2.0.0';
const enc = new TextEncoder();
const dec = new TextDecoder();

const PROVIDERS = {
  twitch: {
    auth: 'https://id.twitch.tv/oauth2/authorize',
    token: 'https://id.twitch.tv/oauth2/token',
    id: e => e.TWITCH_CLIENT_ID, secret: e => e.TWITCH_CLIENT_SECRET,
    scope: 'chat:read chat:edit channel:read:redemptions moderator:manage:banned_users moderator:manage:chat_messages moderator:manage:chat_settings channel:manage:vips channel:manage:moderators channel:manage:redemptions',
    extra: { force_verify: 'true' }, pkce: false
  },
  kick: {
    auth: 'https://id.kick.com/oauth/authorize',
    token: 'https://id.kick.com/oauth/token',
    id: e => e.KICK_CLIENT_ID, secret: e => e.KICK_CLIENT_SECRET,
    scope: 'user:read channel:read chat:write events:subscribe moderation:ban moderation:chat_message:manage channel:rewards:read channel:rewards:write',
    extra: {}, pkce: true
  },
  youtube: {
    auth: 'https://accounts.google.com/o/oauth2/v2/auth',
    token: 'https://oauth2.googleapis.com/token',
    id: e => e.GOOGLE_CLIENT_ID, secret: e => e.GOOGLE_CLIENT_SECRET,
    scope: 'https://www.googleapis.com/auth/youtube.force-ssl',
    extra: { access_type: 'offline', prompt: 'consent', include_granted_scopes: 'true' }, pkce: true
  }
};
const YT_PATHS = new Set(['videos', 'channels', 'search', 'liveChat/messages']);

// --- utils
const origins = env => String(env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim().replace(/\/+$/, '')).filter(Boolean);
function originAllowed(env, origin) {
  if (!origin) return false;
  const list = origins(env);
  if (!list.length) return true;
  return list.includes(origin);
}
function cors(env, req, extra) {
  const o = req.headers.get('Origin') || '';
  const h = {
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
  };
  h['Access-Control-Allow-Origin'] = o && originAllowed(env, o) ? o : (origins(env).length ? 'null' : '*');
  return Object.assign(h, extra || {});
}
const json = (env, req, data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: cors(env, req, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }) });
const b64url = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64url = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), c => c.charCodeAt(0));

// el state va cifrado (return url + verifier de pkce)
async function stateKey(env) {
  const seed = env.STATE_SECRET || [env.TWITCH_CLIENT_SECRET, env.KICK_CLIENT_SECRET, env.GOOGLE_CLIENT_SECRET].filter(Boolean).join('|') || 'tyrachat';
  const raw = await crypto.subtle.digest('SHA-256', enc.encode('tyrachat-state:' + seed));
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
async function seal(env, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await stateKey(env), enc.encode(JSON.stringify(obj)));
  return b64url(iv) + '.' + b64url(ct);
}
async function unseal(env, s) {
  const [iv, ct] = String(s || '').split('.');
  if (!iv || !ct) throw new Error('state');
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64url(iv) }, await stateKey(env), unb64url(ct));
  return JSON.parse(dec.decode(pt));
}
function backTo(ret, params) {
  const u = new URL(ret);
  u.hash = new URLSearchParams(params).toString();
  return Response.redirect(u.toString(), 302);
}

// --- oauth
async function authStart(env, req, url, p) {
  const P = PROVIDERS[p];
  if (!P || !P.id(env) || !P.secret(env)) return new Response('Proveedor no configurado en el servidor', { status: 404 });
  const ret = url.searchParams.get('return') || '';
  let retOrigin = '';
  try { const r = new URL(ret); if (!/^https?:$/.test(r.protocol)) throw 0; retOrigin = r.origin; } catch { return new Response('Falta la página de vuelta (return)', { status: 400 }); }
  if (!origins(env).length && !/^(https:|http:\/\/localhost|http:\/\/127\.0\.0\.1)/.test(retOrigin))
    return new Response('La página de vuelta debe ser https o localhost', { status: 400 });
  if (!originAllowed(env, retOrigin)) return new Response('Esta página no está autorizada en ALLOWED_ORIGINS del servidor: ' + retOrigin, { status: 403 });
  const st = { p, r: ret, n: (url.searchParams.get('nonce') || '').slice(0, 64), t: Date.now() };
  const q = { client_id: P.id(env), redirect_uri: url.origin + '/auth/' + p + '/callback', response_type: 'code', scope: P.scope, ...P.extra };
  if (P.pkce) {
    st.v = b64url(crypto.getRandomValues(new Uint8Array(48)));
    q.code_challenge = b64url(await crypto.subtle.digest('SHA-256', enc.encode(st.v)));
    q.code_challenge_method = 'S256';
  }
  q.state = await seal(env, st);
  return Response.redirect(P.auth + '?' + new URLSearchParams(q), 302);
}
async function authCallback(env, req, url, p) {
  const P = PROVIDERS[p];
  if (!P) return new Response('Proveedor desconocido', { status: 404 });
  let st;
  try { st = await unseal(env, url.searchParams.get('state')); } catch { return new Response('Inicio de sesión caducado o no válido. Vuelve a intentarlo desde TyraChat.', { status: 400 }); }
  if (st.p !== p || Date.now() - st.t > 15 * 60000) return new Response('Inicio de sesión caducado. Vuelve a intentarlo desde TyraChat.', { status: 400 });
  const err = url.searchParams.get('error');
  if (err) return backTo(st.r, { tc: p, nonce: st.n, error: url.searchParams.get('error_description') || err });
  const body = {
    grant_type: 'authorization_code', code: url.searchParams.get('code') || '',
    client_id: P.id(env), client_secret: P.secret(env), redirect_uri: url.origin + '/auth/' + p + '/callback'
  };
  if (st.v) body.code_verifier = st.v;
  let j = {};
  try {
    const r = await fetch(P.token, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body: new URLSearchParams(body) });
    j = await r.json().catch(() => ({}));
    if (!r.ok || !j.access_token) throw new Error(j.error_description || j.message || j.error || ('error ' + r.status));
  } catch (e) {
    return backTo(st.r, { tc: p, nonce: st.n, error: 'No se pudo completar: ' + (e.message || e) });
  }
  return backTo(st.r, {
    tc: p, nonce: st.n, access_token: j.access_token, refresh_token: j.refresh_token || '',
    expires_in: String(j.expires_in || ''), scope: Array.isArray(j.scope) ? j.scope.join(' ') : (j.scope || '')
  });
}
async function authRefresh(env, req, p) {
  const P = PROVIDERS[p];
  if (!P || !P.id(env) || !P.secret(env)) return json(env, req, { error: 'proveedor no configurado' }, 404);
  const o = req.headers.get('Origin');
  if (o && !originAllowed(env, o)) return json(env, req, { error: 'origen no autorizado' }, 403);
  const { refresh_token } = await req.json().catch(() => ({}));
  if (!refresh_token) return json(env, req, { error: 'falta refresh_token' }, 400);
  const r = await fetch(P.token, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token, client_id: P.id(env), client_secret: P.secret(env) })
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.access_token) return json(env, req, { error: j.error_description || j.message || j.error || 'no se pudo renovar' }, r.status === 400 || r.status === 401 ? 401 : 502);
  return json(env, req, { access_token: j.access_token, refresh_token: j.refresh_token || '', expires_in: j.expires_in || 0 });
}

// --- kick
// Clave pública oficial de Kick (docs.kick.com → Webhooks). Se intenta descargar la vigente
// y, si falla, se usa esta.
const KICK_PEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq/+l1WnlRrGSolDMA+A8
6rAhMbQGmQ2SapVcGM3zq8ANXjnhDWocMqfWcTd95btDydITa10kDvHzw9WQOqp2
MZI7ZyrfzJuz5nhTPCiJwTwnEtWft7nV14BYRDHvlfqPUaZ+1KR4OCaO/wWIk/rQ
L/TjY0M70gse8rlBkbo2a8rKhu69RQTRsoaf4DVhDPEeSeI5jVrRDGAMGL3cGuyY
6CLKGdjVEM78g3JfYOvDU/RvfqD7L89TZ3iN94jrmWdGz34JNlEI5hqK8dd7C5EF
BEbZ5jgB8s8ReQV8H+MkuffjdAj3ajDDX3DOJMIut1lBrUVD1AaSrGCKHooWoL2e
twIDAQAB
-----END PUBLIC KEY-----`;
const ALG = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
function pemToDer(pem) {
  const bin = atob(String(pem).replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}
const importPem = pem => crypto.subtle.importKey('spki', pemToDer(pem), ALG, false, ['verify']);
let keyPromise = null;
function getKey() {
  if (!keyPromise) {
    keyPromise = (async () => {
      try {
        const r = await fetch('https://api.kick.com/public/v1/public-key');
        const j = await r.json();
        const pem = j && j.data && (j.data.public_key || j.data.publicKey);
        if (pem) return await importPem(pem);
      } catch {}
      return importPem(KICK_PEM);
    })().catch(e => { keyPromise = null; throw e; });
  }
  return keyPromise;
}
async function kickVerify(env, req, raw) {
  if (String(env.KICK_VERIFY || 'on').toLowerCase() === 'off') return true;
  const id = req.headers.get('Kick-Event-Message-Id'), ts = req.headers.get('Kick-Event-Message-Timestamp'), sig = req.headers.get('Kick-Event-Signature');
  if (!id || !ts || !sig) return false;
  let sigBytes;
  try { sigBytes = Uint8Array.from(atob(sig), c => c.charCodeAt(0)); } catch { return false; }
  // lo firmado es "<message-id>.<timestamp>.<cuerpo crudo>"
  const head = enc.encode(id + '.' + ts + '.');
  const data = new Uint8Array(head.length + raw.length);
  data.set(head, 0); data.set(raw, head.length);
  try { return await crypto.subtle.verify(ALG, await getKey(), sigBytes, data); } catch { return false; }
}
const slugOk = s => /^[a-z0-9_-]{1,50}$/.test(s);
async function kickWebhook(env, req, ctx) {
  const raw = new Uint8Array(await req.arrayBuffer());
  if (!(await kickVerify(env, req, raw))) return new Response('firma no válida', { status: 401 });
  let data; try { data = JSON.parse(dec.decode(raw)); } catch { return new Response('JSON no válido', { status: 400 }); }
  const b = data.broadcaster || {};
  const slug = String(b.channel_slug || b.username || '').toLowerCase();
  if (!slugOk(slug)) return new Response('ok');      // 200 igual, para que Kick no cancele la suscripción
  const msg = JSON.stringify({ type: req.headers.get('Kick-Event-Type') || '', id: req.headers.get('Kick-Event-Message-Id') || '', data });
  const room = env.ROOMS.get(env.ROOMS.idFromName(slug));
  ctx.waitUntil(room.fetch('https://room/broadcast', { method: 'POST', body: msg }).catch(() => {}));
  return new Response('ok');
}

/* Una "sala" por canal de Kick con los WebSockets de TyraChat abiertos.
   Usa la API de hibernación: no gasta mientras nadie escribe. */
export class Room extends DurableObject {
  constructor(state, env) {
    super(state, env);
    this.recent = [];
    // TyraChat manda "ping" cada 30 s; se responde sin despertar al objeto
    this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair('ping', 'pong'));
  }
  async fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === '/broadcast') {
      const msg = await req.text();
      try {
        const m = JSON.parse(msg);
        if (m.id && this.recent.includes(m.id)) return new Response('dup');   // Kick reintenta si tarda
        if (m.id) { this.recent.push(m.id); if (this.recent.length > 200) this.recent.shift(); }
      } catch {}
      for (const ws of this.ctx.getWebSockets()) { try { ws.send(msg); } catch {} }
      return new Response('ok');
    }
    const pair = new WebSocketPair();
    this.ctx.acceptWebSocket(pair[1]);
    pair[1].send(JSON.stringify({ type: 'hello', v: VERSION }));
    return new Response(null, { status: 101, webSocket: pair[0] });
  }
  webSocketMessage(ws, msg) { if (msg === 'ping') { try { ws.send('pong'); } catch {} } }
  webSocketClose(ws, code, reason) { try { ws.close(code, reason); } catch {} }
  webSocketError(ws) { try { ws.close(1011, 'error'); } catch {} }
}
// --- youtube
async function ytProxy(env, req, url) {
  if (!env.YOUTUBE_API_KEY) return json(env, req, { error: { message: 'El servidor no tiene YOUTUBE_API_KEY' } }, 404);
  const o = req.headers.get('Origin');
  if (o && !originAllowed(env, o)) return json(env, req, { error: { message: 'origen no autorizado' } }, 403);
  const path = url.pathname.slice('/yt/api/'.length);
  if (!YT_PATHS.has(path) || req.method !== 'GET') return json(env, req, { error: { message: 'ruta no permitida' } }, 400);
  const q = new URLSearchParams(url.search);
  q.delete('key'); q.delete('mine'); q.set('key', env.YOUTUBE_API_KEY);
  const r = await fetch('https://www.googleapis.com/youtube/v3/' + path + '?' + q);
  return new Response(r.body, { status: r.status, headers: cors(env, req, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }) });
}
async function ytLive(env, req, url) {
  const ch = (url.searchParams.get('channel') || '').trim();
  if (!/^(UC[\w-]{22}|@[^\s/?#]{1,100})$/.test(ch)) return json(env, req, { error: 'canal no válido' }, 400);
  const page = 'https://www.youtube.com/' + (ch[0] === '@' ? encodeURIComponent(ch).replace('%40', '@') : 'channel/' + ch) + '/live';
  try {
    const r = await fetch(page, { headers: { 'Accept-Language': 'es-ES,es;q=0.9,en;q=0.8', 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36', Cookie: 'SOCS=CAI; CONSENT=YES+1' } });
    const html = await r.text();
    const m = /<link rel="canonical" href="https:\/\/www\.youtube\.com\/watch\?v=([\w-]{11})"/.exec(html);
    return json(env, req, { videoId: m ? m[1] : null });
  } catch { return json(env, req, { videoId: null }); }
}

// --- kick emotes
async function kickEmotes(env, req, slug) {
  if (!/^[\w-]{1,40}$/.test(slug)) return json(env, req, { error: 'canal no válido' }, 400);
  const r = await fetch('https://kick.com/emotes/' + slug, { headers: { Accept: 'application/json', 'User-Agent': 'Mozilla/5.0 TyraChat' } });
  if (!r.ok) return json(env, req, { error: 'kick ' + r.status }, 502);
  return new Response(r.body, { status: 200, headers: cors(env, req, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'public, max-age=600' }) });
}

// --- router
export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors(env, req) });
    try {
      if (path === '/') return new Response('TyraChat relay OK · v' + VERSION, { headers: cors(env, req, { 'Content-Type': 'text/plain; charset=utf-8' }) });
      if (path === '/config') {
        const has = p => !!(PROVIDERS[p].id(env) && PROVIDERS[p].secret(env));
        return json(env, req, {
          ok: true, name: 'TyraChat', version: VERSION,
          oauth: { twitch: has('twitch'), kick: has('kick'), youtube: has('youtube') },
          youtube: { proxy: !!env.YOUTUBE_API_KEY, live: true },
          kick: { relay: true, emotes: true },
          originsLocked: origins(env).length > 0
        });
      }
      if (path === '/webhook') return req.method === 'POST' ? kickWebhook(env, req, ctx) : new Response('Usa POST', { status: 405 });
      if (path === '/ws') {
        if ((req.headers.get('Upgrade') || '').toLowerCase() !== 'websocket') return new Response('Se esperaba un WebSocket', { status: 426 });
        const ch = (url.searchParams.get('channel') || '').trim().toLowerCase();
        if (!slugOk(ch)) return new Response('Canal no válido', { status: 400 });
        return env.ROOMS.get(env.ROOMS.idFromName(ch)).fetch(req);
      }
      let m;
      if ((m = /^\/auth\/(twitch|kick|youtube)\/start$/.exec(path))) return authStart(env, req, url, m[1]);
      if ((m = /^\/auth\/(twitch|kick|youtube)\/callback$/.exec(path))) return authCallback(env, req, url, m[1]);
      if ((m = /^\/auth\/(twitch|kick|youtube)\/refresh$/.exec(path)) && req.method === 'POST') return authRefresh(env, req, m[1]);
      if (path.startsWith('/yt/api/')) return ytProxy(env, req, url);
      if (path === '/yt/live') return ytLive(env, req, url);
      if ((m = /^\/kick\/emotes\/([^/]+)$/.exec(path))) return kickEmotes(env, req, decodeURIComponent(m[1]).toLowerCase());
      return new Response('No encontrado', { status: 404, headers: cors(env, req) });
    } catch (e) {
      return json(env, req, { error: 'Error del servidor: ' + (e && e.message || e) }, 500);
    }
  }
};

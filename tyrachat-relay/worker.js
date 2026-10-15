/* TyraChat relay · Cloudflare Worker
   Recibe los webhooks oficiales de Kick (chat, canjes, baneos), verifica que vengan
   de Kick y los reenvía en vivo a TyraChat por WebSocket.

   Rutas:
     POST /webhook            → URL que se pone en la app de Kick (Habilitar webhooks)
     GET  /ws?channel=<slug>  → WebSocket al que se conecta TyraChat
     GET  /                   → comprobación rápida ("TyraChat relay OK")
*/
import { DurableObject } from 'cloudflare:workers';

// Clave pública oficial de Kick (docs.kick.com → Webhooks). Se intenta descargar la vigente
// de https://api.kick.com/public/v1/public-key y, si falla, se usa esta.
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
const enc = new TextEncoder();

function pemToDer(pem) {
  const b64 = String(pem).replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const bin = atob(b64);
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

async function verifyKick(req, raw) {
  const id = req.headers.get('Kick-Event-Message-Id');
  const ts = req.headers.get('Kick-Event-Message-Timestamp');
  const sig = req.headers.get('Kick-Event-Signature');
  if (!id || !ts || !sig) return false;
  let sigBytes;
  try { sigBytes = Uint8Array.from(atob(sig), c => c.charCodeAt(0)); } catch { return false; }
  // Lo firmado es: "<message-id>.<timestamp>.<cuerpo crudo>"
  const head = enc.encode(id + '.' + ts + '.');
  const data = new Uint8Array(head.length + raw.length);
  data.set(head, 0); data.set(raw, head.length);
  return crypto.subtle.verify(ALG, await getKey(), sigBytes, data);
}

const slugOk = s => /^[a-z0-9_-]{1,50}$/.test(s);
const text = (body, status = 200) => new Response(body, {
  status, headers: { 'content-type': 'text/plain; charset=utf-8', 'access-control-allow-origin': '*' }
});

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);

    if (url.pathname === '/webhook') {
      if (req.method !== 'POST') return text('Usa POST', 405);
      const raw = new Uint8Array(await req.arrayBuffer());
      let ok = false;
      try { ok = await verifyKick(req, raw); } catch {}
      if (!ok) return text('firma no válida', 401);

      let body;
      try { body = JSON.parse(new TextDecoder().decode(raw)); } catch { return text('JSON no válido', 400); }
      const b = body.broadcaster || {};
      const slug = String(b.channel_slug || b.username || '').toLowerCase();
      if (!slugOk(slug)) return text('ok');   // se responde 200 igual para que Kick no cancele la suscripción

      const msg = JSON.stringify({
        type: req.headers.get('Kick-Event-Type') || '',
        id: req.headers.get('Kick-Event-Message-Id') || '',
        data: body
      });
      const room = env.ROOMS.get(env.ROOMS.idFromName(slug));
      ctx.waitUntil(room.fetch('https://room/broadcast', { method: 'POST', body: msg }).catch(() => {}));
      return text('ok');
    }

    if (url.pathname === '/ws') {
      if ((req.headers.get('Upgrade') || '').toLowerCase() !== 'websocket') return text('Se esperaba un WebSocket', 426);
      const ch = String(url.searchParams.get('channel') || '').trim().toLowerCase();
      if (!slugOk(ch)) return text('Canal no válido', 400);
      return env.ROOMS.get(env.ROOMS.idFromName(ch)).fetch(req);
    }

    if (url.pathname === '/') return text('TyraChat relay OK');
    return text('No encontrado', 404);
  }
};

/* Una "sala" por canal de Kick: guarda los WebSockets de TyraChat abiertos para ese canal
   y les reenvía cada evento. Usa la API de hibernación, así no gasta mientras nadie escribe. */
export class Room extends DurableObject {
  constructor(state, env) {
    super(state, env);
    // TyraChat manda "ping" cada 30 s; se responde sin despertar al objeto
    this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair('ping', 'pong'));
  }

  async fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === '/broadcast') {
      const msg = await req.text();
      for (const ws of this.ctx.getWebSockets()) { try { ws.send(msg); } catch {} }
      return new Response('ok');
    }
    const pair = new WebSocketPair();
    this.ctx.acceptWebSocket(pair[1]);
    pair[1].send(JSON.stringify({ type: 'hello' }));
    return new Response(null, { status: 101, webSocket: pair[0] });
  }

  webSocketMessage() {}
  webSocketClose(ws, code, reason) { try { ws.close(code, reason); } catch {} }
  webSocketError(ws) { try { ws.close(1011, 'error'); } catch {} }
}

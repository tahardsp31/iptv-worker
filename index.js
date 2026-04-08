import http from "http";
import fetch, { Request, Response, Headers } from "node-fetch";

// ============================================================
// Global Variables
// ============================================================

const SERVER_SCORE = new Map();
const MAC_FAIL = new Map();
const ACTIVE_SESSIONS = new Map();
const TOKEN_CACHE = new Map();

const FAIL_TTL = 30000;

let G_SETTINGS = {};
let G_STIME = Date.now();

// ============================================================
// Auto Servers
// ============================================================
// ============================================================
// Auto Servers
// ============================================================

const AUTO_PORTALS = [
"dinodox.sbs",
"n604.cloud",
"secretservice.cc",
"alasadino.com",
"line.dino-ott.ru",
"cnamedi.cdn-only.cloud",
"smart.cwdn.cx",
"main.cwdn.cx",
"line.ottcdn.net",
"esogalaxiusnext.tech",
"d5.myottes.me",
"d.tvplusfr.com",
"live.vooc.org",
"line.venomtv.me",
"suiptv265.xyz",
"line.rs4ott.com",
"c10.myottes.me",
"line.din-ott.com",
"topiptv.xyz",
"76245-hong.dn-4kott.com",
"30198-puppy.ott-cdn.me",
"10431-plan.ott-cdn.me",
"activeiptv.sbs",
"sbhgoldpro.org",
"24974-lakes.ott-di.com",
"41877-toe.ott-cdn.me"

]

// ============================================================
// Auto MAC
// ============================================================

const AUTO_MACS = [
"00:1A:79:0D:20:AA",
"00:1A:79:B5:A7:3B",
"00:1A:79:69:3F:2E",
"00:1A:79:40:70:4F",
"00:1A:79:C7:BA:1D",
"00:1A:79:F9:EB:51",
"00:1A:79:5E:f8:2a",
"00:1A:79:b7:b2:cf",
"00:1A:79:c7:2F:d0",
"00:1A:79:05:f5:76",
"00:1A:79:53:bc:aa",
"00:1A:79:eb:7a:46",
"00:1A:79:05:43:d6",
"00:1A:79:36:30:63",
"00:1A:79:5e:0d:cb",
"00:1A:79:83:11:19",
"00:1A:79:a9:ba:c6",
"00:1A:79:39:7e:44",
"00:1A:79:40:70:4f",
"00:1A:79:d6:f1:71",
"00:1A:79:01:b5:99",
"00:1A:79:3e:4f:89",
"00:1A:79:09:92:e5",
"00:1A:79:46:43:ae",
"00:1A:79:85:75:F0",
"00:1A:79:23:BB:3E",
"00:1A:79:9B:DC:88",
"00:1A:79:09:9E:1F",
"00:1A:79:7F:A0:5F",
"00:1A:79:64:23:72",
"00:1A:79:9B:DC:88",
"00:1A:79:C4:0B:4C",
"00:1A:79:41:19:A1",
"00:1A:79:B5:B2:F6",
"00:1A:79:19:3F:59",
"00:1A:79:F0:72:E4",
"00:1A:79:56:F2:A9",
"00:1A:79:D4:1F:A9",
"00:1A:79:63:23:50",
"00:1A:79:7D:12:48",
"00:1A:79:B6:49:E8",
"00:1A:79:69:3F:2E",
"00:1A:79:AB:D2:3F",
"00:1A:79:56:5B:25",
"00:1A:79:01:0A:7D",
"00:1A:79:C7:BA:1D",
"00:1A:79:8D:AF:8C",
"00:1A:79:3D:CC:86",
"00:1A:79:7B:5F:43",
"00:1A:79:E6:52:EF"
]

// ============================================================
// Ultra Cache System
// ============================================================

const PROFILE_CACHE = new Map()

const TOKEN_TTL = 600000
const PROFILE_TTL = 600000 
const RETRY_COUNT = 2
const RETRY_DELAY = 1200
const RATE_LIMIT_TTL = 60000 // 1 minute rate limit
const MAX_REQUESTS_PER_MINUTE = 3 // Max 3 requests per minute per server

// Rate limiting maps
const SERVER_REQUEST_COUNT = new Map();
const LAST_REQUEST_TIME = new Map(); 

// ============================================================
// Headers Generator
// ============================================================

function buildHeaders(domain, mac, token=null, variation=0){
  const agents = [
    { ua: "Mozilla/5.0 (QtEmbedded; U; Linux; C)", model: "MAG254" },
    { ua: "MAG200 stbapp ver: 2 rev: 250 Safari/533.3", model: "MAG250" },
    { ua: "Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG256 stbapp ver: 4 rev: 1475 Safari/533.3", model: "MAG256" },
    { ua: "Mozilla/5.0 (Linux; Android 4.4.2; MAG324 Build/KOT49H)", model: "MAG324" },
    { ua: "Mozilla/5.0 (Linux; Android 4.4.2; MAG420 Build/KOT49H)", model: "MAG420" }
  ];
  const selected = agents[variation % agents.length];

  const headers = {
    "User-Agent": selected.ua,
    "X-User-Agent": `Model: ${selected.model}; Link: Ethernet`,
    "Connection": "Keep-Alive",
    "Accept": "*/*",
    "Accept-Encoding": "gzip",
    "Referer": domain,
    "Cookie": `mac=${mac}; stb_lang=en; timezone=Europe/Paris`
  }

  if(token){
    headers["Authorization"] = `Bearer ${token}`
  }

  return headers
}


// ============================================================
// Handshake
// ============================================================

async function handshake(domain, mac){
  const key = domain + mac
  const cached = TOKEN_CACHE.get(key)
  if (cached && (Date.now() - cached.ts < 3600000)) return cached.token

  const variations = [0, 1, 2, 3, 4];
  const actions = ["handshake", "get_token"];
  
  for (const v of variations) {
    for (const action of actions) {
      try{
        await new Promise(r => setTimeout(r, 300)) 
        const url = `${domain}/portal.php?type=stb&action=${action}&token=&JsHttpRequest=1-xml`
        const headers = buildHeaders(domain, mac, null, v);
        
        let res = await fetch(url, { headers, keepalive:true })
        
        if (res.status === 405) {
          res = await fetch(url, { method: 'POST', headers, keepalive:true })
        }

        if(!res.ok) {
          if(res.status === 429 || res.status === 458) {
            MAC_FAIL.set(key, Date.now() + 60000);
            await new Promise(r => setTimeout(r, 800));
            continue;
          }
          if(res.status === 456 || res.status === 403 || res.status === 405) continue;
          return null;
        }

        const data = await res.json()
        const token = data?.js?.token || data?.token || null
        if(token){
          TOKEN_CACHE.set(key,{ token, ts:Date.now() })
          return token
        }
      }catch(e){}
    }
  }
  return null
}


// ============================================================
// Profile
// ============================================================

async function getProfile(domain, mac, token){

  try{

    await new Promise(r => setTimeout(r, 300))

    const url = `${domain}/portal.php?type=stb&action=get_profile&JsHttpRequest=1-xml`

    const res = await fetch(url,{
      headers: buildHeaders(domain, mac, token),
      keepalive:true
    })

    if(res.status === 456 || res.status === 403){
      TOKEN_CACHE.delete(domain+mac)
      return false
    }

    return res.ok

  }catch(e){ return false }
}


// ============================================================
// Create Link
// ============================================================

async function createLink(domain, mac, token, channelId){

  try{

    await new Promise(r => setTimeout(r, 200))

    const cmd = `ffmpeg http://localhost/ch/${channelId}`

    const url =
`${domain}/portal.php?type=itv&action=create_link&cmd=${encodeURIComponent(cmd)}&JsHttpRequest=1-xml`

    const res = await fetch(url,{
      headers: buildHeaders(domain, mac, token),
      keepalive:true
    })

    if(!res.ok) return null

    const data = await res.json()

    return data?.js?.cmd || null

  }catch(e){}

  return null
}


// ============================================================
// Build Stream
// ============================================================

async function buildStream(server, mac, channelId, isRetry=false){

  try{

    await new Promise(r => setTimeout(r, 300)) // anti spam 

    // 1. Handshake
    const token = await handshake(server, mac)
    if(!token) return null

    // 2. Profile
    await getProfile(server, mac, token)

    // 3. Create Link
    const cmd = await createLink(server, mac, token, channelId)

    if (!cmd) {
      TOKEN_CACHE.delete(server + mac)
      if (!isRetry){
        await new Promise(r => setTimeout(r, 500))
        return await buildStream(server, mac, channelId, true)
      }
      return null
    }

    // 4. Play
    return cmd
      .replace("ffmpeg ", "")
      .replace("http://localhost", server)

  }catch(e){ 
    return null 
  }
}

// ============================================================
// Ultra Sort
// ============================================================

function sortServers(){

  return [...AUTO_PORTALS]
  .sort((a,b)=>{

    const sa =
    SERVER_SCORE.get(a) || 0

    const sb =
    SERVER_SCORE.get(b) || 0

    return sb - sa

  })

}

// ============================================================
// Ultra Auto Create Link
// ============================================================

async function autoCreateLink(channelId){

  const domains = sortServers()

  const tasks = []

  for(const domain of domains){

    const macs =
    DOMAIN_MAC_MAP[domain] ||
    AUTO_MACS.slice(0,6)

    for(const mac of macs){

      tasks.push(
        tryCreate(
          `http://${domain}`,
          mac,
          channelId
        )
      )

    }

  }

  const result =
  await Promise.any(tasks)
  .catch(()=>null)

  return result || null

}

// ============================================================
// Ultra Try
// ============================================================

async function tryCreate(domain, mac, channelId){

  const failKey = domain + mac

  const fail = MAC_FAIL.get(failKey)

  if (fail && Date.now() - fail < FAIL_TTL){
    return null
  }

  try{

    const controller =
    new AbortController()

    const timeout =
    setTimeout(()=>{
      controller.abort()
    },1500)

    const stream =
    await buildStream(
      domain,
      mac,
      channelId
    )

    clearTimeout(timeout)

    if(stream){

      const score =
      SERVER_SCORE.get(domain) || 0

      SERVER_SCORE.set(
        domain,
        score + 1
      )

      return stream
    }

    MAC_FAIL.set(
      failKey,
      Date.now()
    )

    return null

  }catch(e){

    MAC_FAIL.set(
      failKey,
      Date.now()
    )

    return null
  }

}

const macCache = new Map();
const serverMacCache = new Map();

const ultraMacCache = new Map();
const ULTRA_MAC_TTL_MS = 90000;
const ULTRA_MAC_MAX = 800;

// ============================================================
// DOMAIN + MAC MAP
// ============================================================

const DOMAIN_MAC_MAP = {
  "main.cwdn.cx": [],
  "wowtv.cc": [],
  "444.tvdragon.com": [],
  "line.dino-ott.ru": []

};


function getAllDomains() {
  return Object.keys(DOMAIN_MAC_MAP);
}

function ultraMacGet(key) {
  const v = ultraMacCache.get(key);
  if (!v) return null;
  if (Date.now() - v.ts > ULTRA_MAC_TTL_MS) { ultraMacCache.delete(key); return null; }
  return v.mac || null;
}

function ultraMacSet(key, mac) {
  if (!mac) return;
  while (ultraMacCache.size >= ULTRA_MAC_MAX) { const k = ultraMacCache.keys().next().value; ultraMacCache.delete(k); }
  ultraMacCache.set(key, { mac, ts: Date.now() });
}

const SERVER_MAC_CACHE_MAX = 1200;
function serverMacCacheSet(key, mac) {
  if (!mac) return;
  if (serverMacCache.size >= SERVER_MAC_CACHE_MAX) { const k = serverMacCache.keys().next().value; serverMacCache.delete(k); }
  serverMacCache.set(key, mac);
}

function forceMacTemporarilyBlocked(mac, ttlMs) {
  if (!mac) return;
  const ms = typeof ttlMs === 'number' ? ttlMs : 15000;
  _MS.failed[mac] = Date.now() + ms;
  if (_MS.macs[_MS.primaryIdx]?.mac === mac && _MS.macs.length) {
    _MS.primaryIdx = (_MS.primaryIdx + 1) % _MS.macs.length;
  }
}

let G_SERVERS = null, G_SRVTIME = 0;
let G_TOKENS = new Map();
const connectionPool = new Map();
const CONNECTION_TTL = 3500;

// Global Live Cache
let G_ACTIVE_SERVERS = null;
let G_ACTIVE_MACS = null;
let G_CACHE_TIME = 0;
const LIVE_CACHE_TTL = 180000; // 3 min
// ACTIVE_SESSIONS is already declared at top of file

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const DEFAULT_MACS = [
      "00:1A:79:33:DE:11","00:1A:79:44:BC:22","00:1A:79:55:AA:33","00:1A:79:44:EE:44","00:1A:79:32:00:55",
      "00:1A:79:33:AA:66","00:1A:79:55:00:77","00:1A:79:44:00:88","00:1A:79:22:11:99","00:1A:79:33:BB:00"
    ];

    const CORS = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };

    const userAgent = request.headers.get('User-Agent') || '';
    const isTV = userAgent.includes('SMART-TV') || userAgent.includes('WebTV') || userAgent.includes('TV') ||
      userAgent.includes('SmartTV') || userAgent.includes('BRAVIA') || userAgent.includes('LGTV') || userAgent.includes('Vizio');

    if (request.method === 'OPTIONS') return new Response(null, { headers: CORS, status: 204 });
    if (request.method === 'HEAD') return new Response(null, { status: 200, headers: { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/x-mpegurl; charset=utf-8' } });

    const db = env.venom_db || env.venom_tokens_db || env.DB || env.d1 || null;
    if (db) { try { await initDB(db); } catch (e) { } }

    if (path === '/api/tokens' && request.method === 'GET') return apiGetTokens(db, CORS);
    if (path === '/api/tokens/create' && request.method === 'POST') return apiCreateToken(request, db, CORS);
    if (path === '/api/tokens/delete' && request.method === 'POST') return apiDeleteToken(request, db, CORS);
    if (path === '/api/tokens/update' && request.method === 'POST') return apiUpdateToken(request, db, CORS);
    if (path === '/api/tokens/validate' && request.method === 'GET') return apiValidateToken(db, CORS, url);
    if (path === '/api/tokens/usage' && request.method === 'GET') return apiGetTokenUsage(db, CORS, url);
    if (path === '/api/tokens/packages/add' && request.method === 'POST') return apiAddPackageToToken(request, db, CORS);
    if (path === '/api/tokens/packages/add-multiple' && request.method === 'POST') return apiAddMultiplePackagesToToken(request, db, CORS);
    if (path === '/api/tokens/packages/remove' && request.method === 'POST') return apiRemovePackageFromToken(request, db, CORS);
    if (path === '/api/tokens/packages/reorder' && request.method === 'POST') return apiReorderTokenPackages(request, db, CORS);
    if (path === '/api/tokens/days/add' && request.method === 'POST') return apiAddDays(request, db, CORS);
    if (path === '/api/tokens/days/remove' && request.method === 'POST') return apiRemoveDays(request, db, CORS);
    if (path === '/api/tokens/block-ip' && request.method === 'POST') return apiBlockIP(request, db, CORS);
    if (path === '/api/tokens/blocked-ips' && request.method === 'GET') return apiGetBlockedIPs(db, CORS, url);

    if (path === '/api/internal/stats' && request.method === 'GET') return await apiGetInternalStats(env, CORS);

    if (path === '/api/macs' && request.method === 'GET') return apiGetMacs(db, CORS, DEFAULT_MACS);
    if (path === '/api/macs' && request.method === 'POST') return apiSaveMacs(request, db, CORS);
    if (path === '/api/macs/update' && request.method === 'POST') return apiUpdateMac(request, db, CORS);
    if (path === '/api/macs/reset-stats' && request.method === 'POST') return apiResetMacStats(request, db, CORS);
    if (path === '/api/macs/list' && request.method === 'GET') return apiGetMacsList(db, CORS, DEFAULT_MACS);
    if (path === '/api/macs/pool' && request.method === 'GET') return apiGetMacPool(db, CORS, DEFAULT_MACS);

    if (path === '/api/packages' && request.method === 'GET') {
      if (env.PACKAGES_KV) {
        try {
          const cached = await env.PACKAGES_KV.get("all_packages", { type: "json" });
          if (cached) return new Response(JSON.stringify(cached), { headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=120", ...CORS } });
        } catch (e) { }
      }
      let data;
      if (db) {
        try {
          const result = await db.prepare('SELECT * FROM packages ORDER BY sort_order ASC, name ASC').all();
          const pkgs = {};
          if (result && result.results) result.results.forEach(r => { pkgs[r.id] = rowToPackage(r); });
          data = { success: true, data: pkgs };
        } catch (e) {
          const result = await db.prepare('SELECT * FROM packages ORDER BY name ASC').all();
          const pkgs = {};
          if (result && result.results) result.results.forEach(r => { pkgs[r.id] = rowToPackage(r); });
          data = { success: true, data: pkgs };
        }
      } else { data = { success: true, data: {} }; }
      if (env.PACKAGES_KV && data.success) ctx.waitUntil(env.PACKAGES_KV.put("all_packages", JSON.stringify(data), { expirationTtl: 120 }));
      return new Response(JSON.stringify(data), { headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=120", ...CORS } });
    }

    if (path === '/api/packages' && request.method === 'POST') return apiSavePackages(request, db, CORS, env);
    if (path === '/api/packages/update' && request.method === 'POST') return apiUpdatePackage(request, db, CORS, env);
    if (path === '/api/packages/reorder' && request.method === 'POST') return apiReorderGlobalPackages(request, db, CORS, env);
    if (path === '/api/packages/delete-all' && request.method === 'POST') return apiDeleteAllPackages(request, db, CORS, env);
    if (path === '/api/packages/delete' && request.method === 'POST') return apiDeletePackage(request, db, CORS, env);
    if (path === '/api/channels/update' && request.method === 'POST') return apiUpdateChannel(request, db, CORS, env);
    if (path === '/api/channels/delete' && request.method === 'POST') return apiDeleteChannel(request, db, CORS, env);
    if (path === '/api/channels/reorder' && request.method === 'POST') return apiReorderChannels(request, db, CORS, env);
    if (path === '/api/channels/domains' && request.method === 'GET') return apiGetChannelDomains(db, CORS);
    if (path === '/api/channels/domains' && request.method === 'POST') return apiSaveChannelDomains(request, db, CORS);
    if (path === '/api/settings' && request.method === 'GET') return apiGetSettings(db, CORS);
    if (path === '/api/settings' && request.method === 'POST') return apiSaveSettings(request, db, CORS);
    if (path === '/api/channels/macs' && request.method === 'POST') return apiSaveChannelMacs(request, db, CORS);
    if (path === '/api/channels/rotate' && request.method === 'POST') return apiRotateChannelDomains(request, db, CORS);

    if (path === '/api/servers' && request.method === 'GET') return apiGetServers(db, CORS);
    if (path === '/api/servers' && request.method === 'POST') return apiSaveServers(request, db, CORS);
    if (path === '/api/servers/delete' && request.method === 'POST') return apiDeleteServer(request, db, CORS);
    if (path === '/api/stats' && request.method === 'GET') return apiGetStats(db, CORS);
    if (path === '/api/upload/m3u' && request.method === 'POST') return apiUploadM3U(request, db, CORS, env);
    if (path === '/api/debug' && request.method === 'GET') return apiDebug(env, db, CORS);
    if (path === '/api/init-db' && request.method === 'POST') return apiInitDB(db, CORS);
    if (path === '/api/init-servers-columns' && request.method === 'POST') return apiInitServerColumns(db, CORS);
    if (path === '/api/init-channel-columns' && request.method === 'POST') return apiInitChannelColumns(db, CORS);
    if (path === '/api/admin/sync-hardcoded' && request.method === 'POST') return apiSyncHardcoded(db, CORS);
    if (path === '/api/admin/sessions/delete' && request.method === 'POST') return await apiDeleteSession(request, env, CORS);
    if (path === '/api/admin/sessions/clear' && request.method === 'POST') return await apiClearSessions(env, CORS);

    if (path === '/playlist.m3u' || path === '/playlist.m3u8') return handlePlaylist(url, db, CORS);
    if (path === '/hls-proxy') return handleHLSProxy(request, url, CORS);
    if (path === '/live') return handleUltraLive(request, env, ctx);
    if (path === '/epg.xml' || path === '/epg.gz') return handleEPGProxy(CORS);
    if (path.startsWith('/live/')) return handleUltraLive(request, env, ctx);

    if (path.startsWith('/live-advanced/')) return handleLiveStreamAdvanced(request, db, CORS);

    if (path === '/' || path === '/panel' || path === '/admin') return renderPanel(url, env, CORS, DEFAULT_MACS, isTV);

    return Response.redirect(url.origin + '/', 302);
  }
};

// ============================================================
// Ultra Fast Live Handler
// ============================================================
async function handleUltraLive(request, env, ctx) {
  const url = new URL(request.url);
  const id = url.searchParams.get("id");
  const ext = url.searchParams.get("ext") || "ts";
  const db = env.venom_db || env.DB || env.d1 || null;

  const channelId = id || url.pathname.split('/').pop()?.split('.')[0];
  const extension = ext || url.pathname.split('.').pop() || 'ts';
  if (!channelId) return new Response("Channel ID required", { status: 400, headers: { 'Access-Control-Allow-Origin': '*' } });

  const userAgent = request.headers.get('User-Agent') || '';
  const isTV = userAgent.includes('SMART-TV') || userAgent.includes('WebTV') || userAgent.includes('TV') ||
    userAgent.includes('SmartTV') || userAgent.includes('BRAVIA') || userAgent.includes('LGTV') || userAgent.includes('Vizio');

  const DEFAULT_MACS = ["00:1A:79:53:bc:aa","00:1A:79:33:DE:11","00:1A:79:44:BC:22","00:1A:79:55:AA:33","00:1A:79:44:EE:44","00:1A:79:32:00:55"];

  const now = Date.now();
  if (!G_ACTIVE_SERVERS || (now - G_CACHE_TIME > LIVE_CACHE_TTL)) {
    if (db) {
      try {
        const [srvs, mcs] = await Promise.all([
          db.prepare('SELECT * FROM servers WHERE active=1 ORDER BY weight DESC').all(),
          db.prepare('SELECT mac, server_id FROM macs WHERE active=1 ORDER BY weight DESC').all()
        ]);
        G_ACTIVE_SERVERS = srvs.results || [];
        G_ACTIVE_MACS = (mcs.results || []).map(r => ({ mac: r.mac, serverId: r.server_id || '' }));
        G_CACHE_TIME = now;
      } catch (e) {}
    }
  }

  const activeServers = G_ACTIVE_SERVERS || [];
  const allMacs = G_ACTIVE_MACS || DEFAULT_MACS.map(m => ({ mac: m, serverId: '' }));

  const pairs = [];
  for (const s of activeServers) {
    const sMacs = allMacs.filter(m => !m.serverId || m.serverId === s.id);
    let finalUrl = s.url;
    try {
        const domList = s.domains ? JSON.parse(s.domains) : [];
        if (domList.length > 0) {
            // Replace IP/Hostname with actual Domain
            const urlobj = new URL(finalUrl);
            finalUrl = finalUrl.replace(urlobj.hostname, domList[0]);
        }
    } catch(e){}
    for (const m of sMacs) pairs.push({ serverUrl: finalUrl, mac: m.mac, serverId: s.id });
  }
  
  if (pairs.length === 0) {
    for (const [domain, macs] of Object.entries(DOMAIN_MAC_MAP)) {
      const serverUrl = `http://${domain}:80`;
      for (const mac of macs) {
        if (!pairs.some(p => p.serverUrl === serverUrl && p.mac === mac)) {
          pairs.push({ serverUrl, mac, serverId: 'map' });
        }
      }
    }
  }

  const ip = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
  const poolKey = `${ip}-${channelId}`;
  connectionPool.set(poolKey, Date.now());

  // ============================================================
  // Ultra Smart Priority Sort
  // ============================================================
  pairs.sort((a, b) => {
    if (a.serverId === 'map' && b.serverId !== 'map') return -1;
    if (b.serverId === 'map' && a.serverId !== 'map') return 1;
    const af = _MS.failed[a.mac] || 0, bf = _MS.failed[b.mac] || 0;
    if (af && !bf) return 1; if (bf && !af) return -1;
    return Math.random() - 0.5;
  });

  const fastTimeout = 3500;
  const slowTimeout = 3500;

  const result = await raceConnections(
    pairs.slice(0, 15), // Increased from 6 to 15 for better coverage
    channelId,
    extension,
    isTV ? slowTimeout : fastTimeout,
    db,
    true,
    ctx
  );

    if (result && !result.error && result.resp) {
      // Session Tracking
      const sessId = ip + '_' + channelId;
      const sessData = {
        id: sessId,
        ip: ip,
        ch: channelId,
        srv: result.serverUrl,
        mac: result.mac,
        ts: Date.now()
      };
      ACTIVE_SESSIONS.set(sessId, sessData);
      if (env.PACKAGES_KV) {
        ctx.waitUntil(env.PACKAGES_KV.put('session:' + sessId, JSON.stringify(sessData), { expirationTtl: 300 }));
      }
      // No more auto-cleaning sessions based on time 
      // Manual deletion only from dashboard

    const mimeTypes = {
      'm3u8': 'application/vnd.apple.mpegurl',
      'mp4': 'video/mp4',
      'mkv': 'video/x-matroska',
      'avi': 'video/x-msvideo',
      'hvd': 'video/mp2t', // Custom or fallback
      'ts': 'video/mp2t'
    };

    return new Response(result.resp.body, {
      status: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Content-Type': mimeTypes[extension] || 'video/mp2t',
        'X-Used-MAC': result.mac, 'X-Server': result.serverUrl,
        'X-Engine': 'Ultra-Fast-V3', 
        'Cache-Control': 'no-cache, no-store, must-revalidate', 
        'X-Accel-Buffering': 'no',
        'Connection': 'keep-alive',
        'Keep-Alive': `timeout=${G_SETTINGS?.keepAliveTimeout || 5}, max=1000`,
        'X-Content-Type-Options': 'nosniff'
      }
    });
  }

  // Record Failed Session
  const errorMsg = (result && result.error) ? result.error : 'فشل مجهول';
  const failSessId = ip + '_fail_' + channelId;
  const failSessData = {
    id: failSessId,
    ip: ip,
    ch: channelId,
    srv: errorMsg,
    mac: 'بدون إجابة',
    status: 'error',
    ts: Date.now()
  };
  ACTIVE_SESSIONS.set(failSessId, failSessData);
  if (env.PACKAGES_KV) {
    ctx.waitUntil(env.PACKAGES_KV.put('session:' + failSessId, JSON.stringify(failSessData), { expirationTtl: 120 }));
  }

  return new Response("Stream unavailable", { status: 503, headers: { 'Access-Control-Allow-Origin': '*' } });
}

// ============================================================
// Internal Stats API
// ============================================================
async function apiGetInternalStats(env, CORS) {
  const scores = {};
  for (const [k, v] of SERVER_SCORE.entries()) scores[k] = v;
  
  const fails = {};
  const now = Date.now();
  for (const [k, v] of MAC_FAIL.entries()) {
    if (now - v < FAIL_TTL) fails[k] = Math.ceil((FAIL_TTL - (now - v))/1000);
  }

  const sessionsMap = new Map();
  const nowTime = Date.now();
  
  // Local isolate sessions
  for (const [sessId, data] of ACTIVE_SESSIONS.entries()) {
    if (nowTime - data.ts > 300000) {
      ACTIVE_SESSIONS.delete(sessId); // cleanup old ones
    } else {
      sessionsMap.set(sessId, { ...data, id: sessId });
    }
  }

  // Global edge sessions from KV
  if (env && env.PACKAGES_KV) {
    try {
      const list = await env.PACKAGES_KV.list({ prefix: 'session:' });
      for (const key of list.keys) {
        const sessId = key.name.substring(8); // remove 'session:'
        if (!sessionsMap.has(sessId)) {
          const val = await env.PACKAGES_KV.get(key.name, "json");
          if (val) sessionsMap.set(sessId, { ...val, id: sessId });
        }
      }
    } catch(e) {}
  }

  return jsonOk({ 
    success: true, 
    data: { 
      scores, 
      fails, 
      cacheSize: TOKEN_CACHE.size,
      sessions: Array.from(sessionsMap.values()),
      uptime: Date.now() - G_STIME 
    } 
  }, CORS);
}

async function apiDeleteSession(request, env, CORS) {
  try {
    const url = new URL(request.url);
    const id = url.searchParams.get('id') || url.searchParams.get('ip');
    if (id) {
      ACTIVE_SESSIONS.delete(id);
      if (env && env.PACKAGES_KV) await env.PACKAGES_KV.delete('session:' + id);
    }
    return jsonOk({ success: true }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiClearSessions(env, CORS) {
  ACTIVE_SESSIONS.clear();
  if (env && env.PACKAGES_KV) {
    try {
      const list = await env.PACKAGES_KV.list({ prefix: 'session:' });
      for (const key of list.keys) {
        await env.PACKAGES_KV.delete(key.name);
      }
    } catch(e) {}
  }
  return jsonOk({ success: true }, CORS);
}

// ============================================================
// تهيئة قاعدة البيانات
// ============================================================
async function initDB(db) {
  if (!db) return;
  await db.exec(`
    CREATE TABLE IF NOT EXISTS tokens (
      token TEXT PRIMARY KEY, username TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
      packages TEXT DEFAULT '[]', packages_order TEXT DEFAULT '[]', max_devices INTEGER DEFAULT 1,
      active_devices INTEGER DEFAULT 0, is_active INTEGER DEFAULT 1, last_used INTEGER, total_usage INTEGER DEFAULT 0,
      usage_history TEXT DEFAULT '[]', watched_channels TEXT DEFAULT '[]', last_channel TEXT,
      last_ip TEXT, blocked_ips TEXT DEFAULT '[]', custom_channels TEXT DEFAULT '[]'
    );
    CREATE TABLE IF NOT EXISTS packages (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, icon TEXT DEFAULT '', channels TEXT DEFAULT '[]',
      created_at INTEGER NOT NULL, sort_order INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS macs (
      id TEXT PRIMARY KEY, mac TEXT NOT NULL UNIQUE, weight INTEGER DEFAULT 5, active INTEGER DEFAULT 1,
      success_count INTEGER DEFAULT 0, fail_count INTEGER DEFAULT 0, total_requests INTEGER DEFAULT 0,
      avg_response_time REAL DEFAULT 0, last_used INTEGER, server_id TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS servers (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL, weight INTEGER DEFAULT 5, active INTEGER DEFAULT 1,
      success_count INTEGER DEFAULT 0, fail_count INTEGER DEFAULT 0, total_requests INTEGER DEFAULT 0,
      avg_response_time REAL DEFAULT 0, domains TEXT DEFAULT '[]', macs TEXT DEFAULT '[]'
    );
    CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
  `);
  try { await db.exec('ALTER TABLE macs ADD COLUMN server_id TEXT DEFAULT ""'); } catch (e) { }
  try { await db.exec('ALTER TABLE packages ADD COLUMN sort_order INTEGER DEFAULT 0'); } catch (e) { }
  try { await db.exec('ALTER TABLE servers ADD COLUMN domains TEXT DEFAULT "[]"'); } catch (e) { }
  try { await db.exec('ALTER TABLE servers ADD COLUMN macs TEXT DEFAULT "[]"'); } catch (e) { }

}

// ============================================================
// Database Functions
// ============================================================

async function ensureServerIdCol(db) {
  try {
    await db.exec(`ALTER TABLE macs ADD COLUMN server_id TEXT DEFAULT ''`);
  } catch (e) {}
}

// ============================================================
// دوال مساعدة
// ============================================================
function jsonOk(data, CORS) { return new Response(JSON.stringify(data), { headers: { 'Content-Type': 'application/json', ...CORS } }); }
function jsonErr(msg, CORS, status = 500) { return new Response(JSON.stringify({ success: false, error: msg }), { status, headers: { 'Content-Type': 'application/json', ...CORS } }); }
function parseJSON(str, def) { try { return JSON.parse(str || ''); } catch (e) { return def; } }
function genToken() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let token = '';
  for (let i = 0; i < 6; i++) token += chars[Math.floor(Math.random() * chars.length)];
  return token;
}

function rowToToken(r) {
  if (!r) return null;
  const now = Date.now();
  return {
    token: r.token, username: r.username, createdAt: r.created_at, expiresAt: r.expires_at,
    packages: parseJSON(r.packages, []), packagesOrder: parseJSON(r.packages_order, []),
    maxDevices: r.max_devices || 1, activeDevices: r.active_devices || 0, isActive: r.is_active === 1,
    lastUsed: r.last_used, totalUsage: r.total_usage || 0, usageHistory: parseJSON(r.usage_history, []),
    watchedChannels: parseJSON(r.watched_channels, []), lastChannel: r.last_channel, lastIp: r.last_ip,
    blockedIPs: parseJSON(r.blocked_ips, []), blockedIPsCount: parseJSON(r.blocked_ips, []).length,
    isExpired: now > r.expires_at, daysRemaining: Math.max(0, Math.floor((r.expires_at - now) / 86400000)),
    status: now > r.expires_at ? 'expired' : (r.is_active ? 'active' : 'inactive')
  };
}

function rowToMAC(r) {
  const total = r.total_requests || 0;
  const successRate = total > 0 ? Math.round((r.success_count || 0) / total * 100) : null;
  return { id: r.id, mac: r.mac, weight: r.weight || 5, active: r.active === 1, successCount: r.success_count || 0, failCount: r.fail_count || 0, totalRequests: total, avgResponseTime: r.avg_response_time || 0, lastUsed: r.last_used, serverId: r.server_id || '', successRate };
}

function rowToPackage(r) {
  var raw = r.icon || '';
  var parts = raw.split('||');
  return { id: r.id, name: r.name, icon: parts[0] || '', logo: parts[1] || '', channels: parseJSON(r.channels, []) };
}

function packIconLogo(icon, logo) {
  var i = (icon || '').replace('||', '|');
  var l = (logo || '').replace('||', '|');
  return l ? (i + '||' + l) : i;
}

// ============================================================
// API التوكنات
// ============================================================
async function apiGetTokens(db, CORS) {
  if (!db) return jsonErr('D1 not configured. Add binding "venom_db"', CORS);
  try {
    const { results } = await db.prepare('SELECT * FROM tokens ORDER BY created_at DESC').all();
    return jsonOk({ success: true, data: results.map(rowToToken) }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiCreateToken(request, db, CORS) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    const { username, duration, packages, maxDevices } = await request.json();
    if (!username || !duration) return jsonErr('username and duration required', CORS, 400);
    const token = genToken();
    const now = Date.now();
    const expiresAt = now + duration * 86400000;
    const pkgsStr = JSON.stringify(packages || []);
    await db.prepare('INSERT INTO tokens (token,username,created_at,expires_at,packages,packages_order,max_devices,is_active,total_usage,usage_history,watched_channels,blocked_ips,custom_channels) VALUES (?,?,?,?,?,?,?,1,0,?,?,?,?)')
      .bind(token, username, now, expiresAt, pkgsStr, pkgsStr, maxDevices || 1, '[]', '[]', '[]', '[]').run();
    const row = await db.prepare('SELECT * FROM tokens WHERE token = ?').bind(token).first();
    return jsonOk({ success: true, data: rowToToken(row) }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiDeleteToken(request, db, CORS) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    const { token } = await request.json();
    await db.prepare('DELETE FROM tokens WHERE token = ?').bind(token).run();
    invalidateTokenCache(token);
    return jsonOk({ success: true }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiUpdateToken(request, db, CORS) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    const { token, updates } = await request.json();
    const sets = [], vals = [];
    if (updates.username !== undefined) { sets.push('username = ?'); vals.push(updates.username); }
    if (updates.maxDevices !== undefined) { sets.push('max_devices = ?'); vals.push(updates.maxDevices); }
    if (updates.isActive !== undefined) { sets.push('is_active = ?'); vals.push(updates.isActive ? 1 : 0); }
    if (updates.packages !== undefined) {
      sets.push('packages = ?'); sets.push('packages_order = ?');
      vals.push(JSON.stringify(updates.packages)); vals.push(JSON.stringify(updates.packages));
    }
    if (!sets.length) return jsonOk({ success: true }, CORS);
    vals.push(token);
    await db.prepare('UPDATE tokens SET ' + sets.join(', ') + ' WHERE token = ?').bind(...vals).run();
    invalidateTokenCache(token);
    return jsonOk({ success: true }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiValidateToken(db, CORS, url) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    const token = url.searchParams.get('token');
    if (!token) return jsonErr('Token required', CORS, 400);
    const row = await db.prepare('SELECT * FROM tokens WHERE token = ?').bind(token).first();
    if (!row) return jsonErr('Token not found', CORS, 404);
    const t = rowToToken(row);
    if (t.isExpired || !t.isActive) return jsonErr('Token expired or inactive', CORS, 403);
    return jsonOk({ success: true, valid: true, username: t.username, packages: t.packages, daysRemaining: t.daysRemaining }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiGetTokenUsage(db, CORS, url) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    const token = url.searchParams.get('token');
    const row = await db.prepare('SELECT * FROM tokens WHERE token = ?').bind(token).first();
    if (!row) return jsonErr('Token not found', CORS, 404);
    const t = rowToToken(row);
    const pkgRows = await db.prepare('SELECT * FROM packages').all();
    const pkgsMap = {};
    pkgRows.results.forEach(r => pkgsMap[r.id] = rowToPackage(r));
    t.packagesWithDetails = (t.packages || []).map(id => ({ id, ...(pkgsMap[id] || { name: id, icon: '', channels: [] }) }));
    return jsonOk({ success: true, data: t }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiAddPackageToToken(request, db, CORS) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    const { token, packageId } = await request.json();
    const row = await db.prepare('SELECT packages FROM tokens WHERE token = ?').bind(token).first();
    if (!row) return jsonErr('Token not found', CORS, 404);
    const pkgs = parseJSON(row.packages, []);
    if (pkgs.includes(packageId)) return jsonErr('Package already added', CORS, 400);
    pkgs.push(packageId);
    const s = JSON.stringify(pkgs);
    await db.prepare('UPDATE tokens SET packages = ?, packages_order = ? WHERE token = ?').bind(s, s, token).run();
    invalidateTokenCache(token);
    return jsonOk({ success: true, packages: pkgs }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiAddMultiplePackagesToToken(request, db, CORS) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    const { token, packageIds } = await request.json();
    if (!Array.isArray(packageIds) || !packageIds.length) return jsonErr('packageIds array required', CORS, 400);
    const row = await db.prepare('SELECT packages FROM tokens WHERE token = ?').bind(token).first();
    if (!row) return jsonErr('Token not found', CORS, 404);
    const pkgs = parseJSON(row.packages, []);
    const newPkgs = [...new Set([...pkgs, ...packageIds])];
    const s = JSON.stringify(newPkgs);
    await db.prepare('UPDATE tokens SET packages = ?, packages_order = ? WHERE token = ?').bind(s, s, token).run();
    invalidateTokenCache(token);
    return jsonOk({ success: true, packages: newPkgs }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiRemovePackageFromToken(request, db, CORS) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    const { token, packageId } = await request.json();
    const row = await db.prepare('SELECT packages FROM tokens WHERE token = ?').bind(token).first();
    if (!row) return jsonErr('Token not found', CORS, 404);
    const pkgs = parseJSON(row.packages, []).filter(p => p !== packageId);
    const s = JSON.stringify(pkgs);
    await db.prepare('UPDATE tokens SET packages = ?, packages_order = ? WHERE token = ?').bind(s, s, token).run();
    invalidateTokenCache(token);
    return jsonOk({ success: true, packages: pkgs }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiReorderTokenPackages(request, db, CORS) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    const { token, packages } = await request.json();
    const s = JSON.stringify(packages || []);
    await db.prepare('UPDATE tokens SET packages = ?, packages_order = ? WHERE token = ?').bind(s, s, token).run();
    invalidateTokenCache(token);
    return jsonOk({ success: true }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiAddDays(request, db, CORS) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    const { token, days } = await request.json();
    const row = await db.prepare('SELECT expires_at FROM tokens WHERE token = ?').bind(token).first();
    if (!row) return jsonErr('Token not found', CORS, 404);
    const newExp = row.expires_at + days * 86400000;
    await db.prepare('UPDATE tokens SET expires_at = ? WHERE token = ?').bind(newExp, token).run();
    invalidateTokenCache(token);
    return jsonOk({ success: true, expiresAt: newExp, daysRemaining: Math.max(0, Math.floor((newExp - Date.now()) / 86400000)) }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiRemoveDays(request, db, CORS) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    const { token, days } = await request.json();
    const row = await db.prepare('SELECT expires_at FROM tokens WHERE token = ?').bind(token).first();
    if (!row) return jsonErr('Token not found', CORS, 404);
    const newExp = Math.max(Date.now(), row.expires_at - days * 86400000);
    await db.prepare('UPDATE tokens SET expires_at = ? WHERE token = ?').bind(newExp, token).run();
    invalidateTokenCache(token);
    return jsonOk({ success: true, expiresAt: newExp, daysRemaining: Math.max(0, Math.floor((newExp - Date.now()) / 86400000)) }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiBlockIP(request, db, CORS) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    const { token, ip, action } = await request.json();
    const row = await db.prepare('SELECT blocked_ips FROM tokens WHERE token = ?').bind(token).first();
    if (!row) return jsonErr('Token not found', CORS, 404);
    let ips = parseJSON(row.blocked_ips, []);
    if (action === 'block') { if (!ips.includes(ip)) ips.push(ip); }
    else if (action === 'unblock') { ips = ips.filter(x => x !== ip); }
    await db.prepare('UPDATE tokens SET blocked_ips = ? WHERE token = ?').bind(JSON.stringify(ips), token).run();
    invalidateTokenCache(token);
    return jsonOk({ success: true, blockedIPs: ips }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiGetBlockedIPs(db, CORS, url) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    const token = url.searchParams.get('token');
    const row = await db.prepare('SELECT blocked_ips FROM tokens WHERE token = ?').bind(token).first();
    if (!row) return jsonErr('Token not found', CORS, 404);
    return jsonOk({ success: true, blockedIPs: parseJSON(row.blocked_ips, []) }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

// ============================================================
// API عناوين MAC
// ============================================================
async function apiGetMacs(db, CORS, defaultMacs) {
  if (db) await ensureServerIdCol(db);
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    const { results } = await db.prepare('SELECT * FROM macs ORDER BY weight DESC, id ASC').all();
    if (results.length === 0) {
      for (let i = 0; i < defaultMacs.length; i++) {
        try { await db.prepare('INSERT OR IGNORE INTO macs (id,mac,weight,active,success_count,fail_count,total_requests,avg_response_time) VALUES (?,?,5,1,0,0,0,0)').bind((i + 1).toString(), defaultMacs[i]).run(); } catch (e) { }
      }
      const { results: r2 } = await db.prepare('SELECT * FROM macs ORDER BY weight DESC').all();
      return jsonOk({ success: true, data: r2.map(rowToMAC) }, CORS);
    }
    return jsonOk({ success: true, data: results.map(rowToMAC) }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiSaveMacs(request, db, CORS) {
  if (!db) return jsonErr('D1 not configured', CORS);
  await ensureServerIdCol(db);
  try {
    const { macs } = await request.json();
    await db.prepare('DELETE FROM macs').run();
    for (const m of macs) {
      await db.prepare('INSERT INTO macs (id,mac,weight,active,success_count,fail_count,total_requests,avg_response_time,last_used,server_id) VALUES (?,?,?,?,?,?,?,?,?,?)')
        .bind(m.id || Date.now().toString(), m.mac, m.weight || 5, m.active ? 1 : 0, m.successCount || 0, m.failCount || 0, m.totalRequests || 0, m.avgResponseTime || 0, m.lastUsed || null, m.serverId || '').run();
    }
    return jsonOk({ success: true }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiUpdateMac(request, db, CORS) {
  if (!db) return jsonErr('D1 not configured', CORS);
  await ensureServerIdCol(db);
  try {
    const { macId, updates } = await request.json();
    const sets = [], vals = [];
    if (updates.mac !== undefined) { sets.push('mac = ?'); vals.push(updates.mac); }
    if (updates.weight !== undefined) { sets.push('weight = ?'); vals.push(updates.weight); }
    if (updates.active !== undefined) { sets.push('active = ?'); vals.push(updates.active ? 1 : 0); }
    if (updates.serverId !== undefined) { sets.push('server_id = ?'); vals.push(updates.serverId); }
    if (!sets.length) return jsonOk({ success: true }, CORS);
    vals.push(macId);
    await db.prepare('UPDATE macs SET ' + sets.join(', ') + ' WHERE id = ?').bind(...vals).run();
    return jsonOk({ success: true }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiResetMacStats(request, db, CORS) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    const { macId } = await request.json();
    await db.prepare('UPDATE macs SET success_count=0,fail_count=0,total_requests=0,avg_response_time=0,last_used=NULL WHERE id=?').bind(macId).run();
    return jsonOk({ success: true }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiGetMacsList(db, CORS, defaultMacs) {
  try {
    if (!db) return jsonOk({ success: true, data: defaultMacs }, CORS);
    const { results } = await db.prepare('SELECT mac FROM macs WHERE active=1 ORDER BY weight DESC').all();
    const list = results.map(r => r.mac);
    return jsonOk({ success: true, data: list.length ? list : defaultMacs }, CORS);
  } catch (e) { return jsonOk({ success: true, data: defaultMacs }, CORS); }
}

// ============================================================
// API الباقات
// ============================================================
async function apiSavePackages(request, db, CORS, env) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    const { packages } = await request.json();
    for (const [id, pkg] of Object.entries(packages)) {
      await db.prepare('INSERT OR REPLACE INTO packages (id,name,icon,channels,created_at,sort_order) VALUES (?,?,?,?,?,?)')
        .bind(id, pkg.name || id, packIconLogo(pkg.icon, pkg.logo), JSON.stringify(pkg.channels || []), Date.now(), pkg.sortOrder || 0).run();
    }
    if (env.PACKAGES_KV) await env.PACKAGES_KV.delete("all_packages");
    return jsonOk({ success: true }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiUpdatePackage(request, db, CORS, env) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    const { packageId, updates } = await request.json();
    const sets = [], vals = [];
    if (updates.name !== undefined) { sets.push('name = ?'); vals.push(updates.name); }
    if (updates.icon !== undefined || updates.logo !== undefined) {
      const cur = await db.prepare('SELECT icon FROM packages WHERE id = ?').bind(packageId).first();
      const curParts = (cur && cur.icon ? cur.icon : '').split('||');
      const newIcon = updates.icon !== undefined ? updates.icon : (curParts[0] || '');
      const newLogo = updates.logo !== undefined ? updates.logo : (curParts[1] || '');
      sets.push('icon = ?'); vals.push(packIconLogo(newIcon, newLogo));
    }
    if (updates.channels !== undefined) { sets.push('channels = ?'); vals.push(JSON.stringify(updates.channels)); }
    if (!sets.length) return jsonOk({ success: true }, CORS);
    vals.push(packageId);
    await db.prepare('UPDATE packages SET ' + sets.join(', ') + ' WHERE id = ?').bind(...vals).run();
    if (env.PACKAGES_KV) await env.PACKAGES_KV.delete("all_packages");
    return jsonOk({ success: true }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiReorderGlobalPackages(request, db, CORS, env) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    const { order } = await request.json();
    if (!Array.isArray(order)) return jsonErr('Order array required', CORS, 400);
    for (let i = 0; i < order.length; i++) await db.prepare('UPDATE packages SET sort_order = ? WHERE id = ?').bind(i, order[i]).run();
    if (env.PACKAGES_KV) await env.PACKAGES_KV.delete("all_packages");
    return jsonOk({ success: true }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiDeleteAllPackages(request, db, CORS, env) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    await db.prepare('DELETE FROM packages').run();
    if (env.PACKAGES_KV) await env.PACKAGES_KV.delete("all_packages");
    return jsonOk({ success: true, message: 'تم حذف جميع الباقات' }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiDeletePackage(request, db, CORS, env) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    const { packageId } = await request.json();
    await db.prepare('DELETE FROM packages WHERE id = ?').bind(packageId).run();
    if (env.PACKAGES_KV) await env.PACKAGES_KV.delete("all_packages");
    return jsonOk({ success: true }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

// ============================================================
// API القنوات
// ============================================================
async function apiGetChannelDomains(db, CORS) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    const row = await db.prepare('SELECT domains FROM channels WHERE id = ?').bind('').first();
    if (!row) return jsonErr('Channel not found', CORS, 404);
    return jsonOk({ success: true, data: parseJSON(row.domains, []) }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiSaveChannelDomains(request, db, CORS) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    const { channelId, domains } = await request.json();
    if (!channelId || !Array.isArray(domains)) return jsonErr('channelId and domains required', CORS, 400);
    
    // Search in packages table since channels are stored in packages
    const packages = await db.prepare('SELECT * FROM packages').all();
    let pkg = null;
    
    for (const p of packages.results || []) {
      const channels = parseJSON(p.channels, []);
      const channel = channels.find(ch => ch.id === channelId);
      if (channel) {
        pkg = p;
        channel.domains = domains;
        channel.current_domain_index = 0;
        await db.prepare('UPDATE packages SET channels = ? WHERE id = ?').bind(JSON.stringify(channels), p.id).run();
        return jsonOk({ success: true }, CORS);
      }
    }
    
    if (!pkg) return jsonErr('Channel not found', CORS, 404);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiGetChannelMacs(request, db, CORS) {
  if (!db) return jsonErr('D1 not configured', CORS);

  try {

    const { channelId } = await request.json();

    if (!channelId)
      return jsonErr('channelId required', CORS, 400);

    const packages =
    await db.prepare('SELECT * FROM packages').all();

    let channelData = null;

    for (const pkg of packages.results || []) {

      const channels =
      parseJSON(pkg.channels, []);

      const channel =
      channels.find(ch => ch.id === channelId);

      if (channel) {

        channelData = {
          macs: channel.macs || []
        };

        break;
      }
    }

    if (!channelData)
      return jsonErr('Channel not found', CORS, 404);

    return jsonOk(
      { success: true, data: channelData.macs },
      CORS
    );

  } catch (e) {
    return jsonErr(e.message, CORS);
  }
}

async function apiSaveChannelMacs(request, db, CORS) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    const { channelId, macs } = await request.json();
    if (!channelId || !Array.isArray(macs)) return jsonErr('channelId and macs required', CORS, 400);
    
    // Search in packages table since channels are stored in packages
    const packages = await db.prepare('SELECT * FROM packages').all();
    let pkg = null;
    
    for (const p of packages.results || []) {
      const channels = parseJSON(p.channels, []);
      const channel = channels.find(ch => ch.id === channelId);
      if (channel) {
        pkg = p;
        channel.macs = macs;
        await db.prepare('UPDATE packages SET channels = ? WHERE id = ?').bind(JSON.stringify(channels), p.id).run();
        return jsonOk({ success: true }, CORS);
      }
    }
    
    if (!pkg) return jsonErr('Channel not found', CORS, 404);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiRotateChannelDomains(request, db, CORS) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    const { channelId } = await request.json();
    if (!channelId) return jsonErr('channelId required', CORS, 400);
    
    // Search in packages table since channels are stored in packages
    const packages = await db.prepare('SELECT * FROM packages').all();
    let pkg = null;
    let channel = null;
    
    for (const p of packages.results || []) {
      const channels = parseJSON(p.channels, []);
      const foundChannel = channels.find(ch => ch.id === channelId);
      if (foundChannel) {
        pkg = p;
        channel = foundChannel;
        break;
      }
    }
    
    if (!channel) return jsonErr('Channel not found', CORS, 404);
    
    const domains = channel.domains || [];
    if (!domains.length) return jsonErr('No domains configured for this channel', CORS);
    
    const nextIndex = ((channel.current_domain_index || 0) + 1) % domains.length;
    channel.current_domain_index = nextIndex;
    
    // Update the package with the modified channel
    const channels = parseJSON(pkg.channels, []);
    const channelIndex = channels.findIndex(ch => ch.id === channelId);
    if (channelIndex !== -1) {
      channels[channelIndex] = channel;
      await db.prepare('UPDATE packages SET channels = ? WHERE id = ?').bind(JSON.stringify(channels), pkg.id).run();
    }
    
    return jsonOk({ 
      success: true, 
      currentDomain: domains[nextIndex], 
      nextIndex, 
      allDomains: domains 
    }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiUpdateChannel(request, db, CORS, env) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    const { packageId, channelId, updates } = await request.json();
    const row = await db.prepare('SELECT channels FROM packages WHERE id = ?').bind(packageId).first();
    if (!row) return jsonErr('Package not found', CORS, 404);
    const channels = parseJSON(row.channels, []);
    const idx = channels.findIndex(c => c.id === channelId);
    if (idx === -1) return jsonErr('Channel not found', CORS, 404);
    channels[idx] = { ...channels[idx], ...updates };
    await db.prepare('UPDATE packages SET channels = ? WHERE id = ?').bind(JSON.stringify(channels), packageId).run();
    if (env.PACKAGES_KV) await env.PACKAGES_KV.delete("all_packages");
    return jsonOk({ success: true }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiDeleteChannel(request, db, CORS, env) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    const { packageId, channelId } = await request.json();
    const row = await db.prepare('SELECT channels FROM packages WHERE id = ?').bind(packageId).first();
    if (!row) return jsonErr('Package not found', CORS, 404);
    const channels = parseJSON(row.channels, []).filter(c => c.id !== channelId);
    await db.prepare('UPDATE packages SET channels = ? WHERE id = ?').bind(JSON.stringify(channels), packageId).run();
    if (env.PACKAGES_KV) await env.PACKAGES_KV.delete("all_packages");
    return jsonOk({ success: true }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiReorderChannels(request, db, CORS, env) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    const { packageId, channels } = await request.json();
    if (!packageId || !Array.isArray(channels)) return jsonErr('packageId and channels required', CORS, 400);
    await db.prepare('UPDATE packages SET channels = ? WHERE id = ?').bind(JSON.stringify(channels), packageId).run();
    if (env.PACKAGES_KV) await env.PACKAGES_KV.delete("all_packages");
    return jsonOk({ success: true }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

// ============================================================
// API الخوادم
// ============================================================
async function apiGetSettings(db, CORS) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    const row = await db.prepare('SELECT value FROM settings WHERE key = ?').bind('adv_settings').first();
    const settings = row ? JSON.parse(row.value) : {
      racePoolSize: 3,
      raceTimeout: 3500,
      fallbackTimeout: 800,
      retryCount: 2,
      retryDelay: 1200,
      keepAliveTimeout: 5
    };
    return jsonOk({ success: true, settings }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiSaveSettings(request, db, CORS) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    const { settings } = await request.json();
    await db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').bind('adv_settings', JSON.stringify(settings)).run();
    G_SETTINGS = settings;
    G_STIME = Date.now();
    return jsonOk({ success: true }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiGetServers(db, CORS) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    const { results } = await db.prepare('SELECT * FROM servers ORDER BY weight DESC').all();
    return jsonOk({ success: true, data: results.map(r => ({ 
      id: r.id, 
      name: r.name, 
      url: r.url, 
      weight: r.weight, 
      active: r.active === 1, 
      successCount: r.success_count || 0, 
      failCount: r.fail_count || 0, 
      totalRequests: r.total_requests || 0,
      domains: parseJSON(r.domains, []),
      macs: parseJSON(r.macs, [])
    })) }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiSaveServers(request, db, CORS) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    const { servers } = await request.json();
    for (const s of servers) {
      await db.prepare('INSERT OR REPLACE INTO servers (id,name,url,weight,active,success_count,fail_count,total_requests,avg_response_time,domains,macs) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
        .bind(
          s.id || Date.now().toString(), 
          s.name, 
          s.url, 
          s.weight || 5, 
          s.active ? 1 : 0, 
          s.successCount || 0, 
          s.failCount || 0, 
          s.totalRequests || 0, 
          s.avgResponseTime || 0,
          JSON.stringify(s.domains || []),
          JSON.stringify(s.macs || [])
        ).run();
    }
    return jsonOk({ success: true }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiDeleteServer(request, db, CORS) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    const { id } = await request.json();
    await db.prepare('DELETE FROM servers WHERE id = ?').bind(id).run();
    return jsonOk({ success: true }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

// ============================================================
// API الإحصائيات
// ============================================================
async function apiGetStats(db, CORS) {
  if (!db) return jsonOk({ success: true, data: { tokens: 0, activeTokens: 0, macs: 0, packages: 0, totalChannels: 0, servers: 0, dbConfigured: false } }, CORS);
  try {
    const now = Date.now();
    const totalT = await db.prepare('SELECT COUNT(*) as c FROM tokens').first();
    const activeT = await db.prepare('SELECT COUNT(*) as c FROM tokens WHERE is_active=1 AND expires_at > ?').bind(now).first();
    const totalM = await db.prepare('SELECT COUNT(*) as c FROM macs').first();
    const activeM = await db.prepare('SELECT COUNT(*) as c FROM macs WHERE active=1').first();
    const totalP = await db.prepare('SELECT COUNT(*) as c FROM packages').first();
    const totalS = await db.prepare('SELECT COUNT(*) as c FROM servers').first();
    const pkgRows = await db.prepare('SELECT channels FROM packages').all();
    let totalChs = 0;
    pkgRows.results.forEach(r => { totalChs += parseJSON(r.channels, []).length; });
    return jsonOk({ success: true, data: { tokens: totalT?.c || 0, activeTokens: activeT?.c || 0, expiredTokens: (totalT?.c || 0) - (activeT?.c || 0), macs: totalM?.c || 0, activeMacs: activeM?.c || 0, packages: totalP?.c || 0, totalChannels: totalChs, servers: totalS?.c || 0, dbConfigured: true } }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

// ============================================================
// رفع ملف M3U
// ============================================================
async function apiUploadM3U(request, db, CORS, env) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    const formData = await request.formData();
    const file = formData.get('file');
    if (!file) return jsonErr('File required', CORS, 400);
    const text = await file.text();
    const lines = text.split('\n');
    const newPackages = {};
    let currentChannel = null;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (line.startsWith('#EXTINF:')) {
        const nameMatch = line.match(/,([^,]+)$/);
        const tvgIdMatch = line.match(/tvg-id="([^"]*)"/);
        const tvgLogoMatch = line.match(/tvg-logo="([^"]*)"/);
        const groupMatch = line.match(/group-title="([^"]*)"/);
        const groupName = (groupMatch ? groupMatch[1].trim() : null) || 'عام';
        const groupId = groupName.replace(/[^a-zA-Z0-9\u0600-\u06FF]/g, '_').toLowerCase().substring(0, 30);
        currentChannel = { id: tvgIdMatch ? tvgIdMatch[1] : ('ch_' + i), name: nameMatch ? nameMatch[1].trim() : 'قناة', url: '', logo: tvgLogoMatch ? tvgLogoMatch[1] : '', group: groupName, packageId: groupId };
        if (!newPackages[groupId]) newPackages[groupId] = { id: groupId, name: groupName, icon: '', channels: [] };
      } else if (line.startsWith('http') && currentChannel) {
        currentChannel.url = line;
        currentChannel.number = newPackages[currentChannel.packageId].channels.length + 1;
        newPackages[currentChannel.packageId].channels.push(currentChannel);
        currentChannel = null;
      }
    }

    for (const [id, pkg] of Object.entries(newPackages)) {
      await db.prepare('INSERT OR REPLACE INTO packages (id,name,icon,channels,created_at) VALUES (?,?,?,?,?)')
        .bind(id, pkg.name, packIconLogo(pkg.icon, pkg.logo), JSON.stringify(pkg.channels), Date.now()).run();
    }
    if (env.PACKAGES_KV) await env.PACKAGES_KV.delete("all_packages");
    const totalChannels = Object.values(newPackages).reduce((s, p) => s + p.channels.length, 0);
    return jsonOk({ success: true, packageCount: Object.keys(newPackages).length, count: totalChannels }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

// ============================================================
// التشخيص وتهيئة قاعدة البيانات
// ============================================================
async function apiDebug(env, db, CORS) {
  const info = { dbConfigured: !!db, kvConfigured: !!env.PACKAGES_KV, timestamp: new Date().toISOString(), bindings: Object.keys(env || {}).filter(k => typeof env[k] === 'object') };
  if (db) {
    try {
      const tables = await db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
      info.tables = tables.results.map(r => r.name);
      info.dbWorking = true;
      const tc = await db.prepare('SELECT COUNT(*) as c FROM tokens').first();
      info.tokenCount = tc?.c || 0;
    } catch (e) { info.dbError = e.message; info.dbWorking = false; }
  }
  if (env.PACKAGES_KV) {
    try { const cached = await env.PACKAGES_KV.get("all_packages"); info.kvWorking = true; info.kvHasData = !!cached; }
    catch (e) { info.kvError = e.message; info.kvWorking = false; }
  }
  return jsonOk({ success: true, debug: info }, CORS);
}

async function apiInitDB(db, CORS) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    await initDB(db);
    const tables = await db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
    return jsonOk({ success: true, message: 'DB initialized', tables: tables.results.map(r => r.name) }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiInitServerColumns(db, CORS) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    // Add domains column
    try { await db.exec('ALTER TABLE servers ADD COLUMN domains TEXT DEFAULT "[]"'); } catch (e) { }
    // Add macs column  
    try { await db.exec('ALTER TABLE servers ADD COLUMN macs TEXT DEFAULT "[]"'); } catch (e) { }
    
    // Check if columns exist
    const info = await db.prepare("PRAGMA table_info(servers)").all();
    const columns = info.results.map(r => r.name);
    
    return jsonOk({ 
      success: true, 
      message: 'Server columns initialized successfully',
      columns: columns,
      hasDomains: columns.includes('domains'),
      hasMacs: columns.includes('macs')
    }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

async function apiInitChannelColumns(db, CORS) {
  return jsonOk({ success: true, message: 'Channels are now stored in packages table. No separate columns needed.' }, CORS);
}

async function apiSyncHardcoded(db, CORS) {
  if (!db) return jsonErr('D1 not configured', CORS);
  try {
    let serversAdded = 0;
    let macsAdded = 0;

    // 1. Sync Servers from AUTO_PORTALS and DOMAIN_MAC_MAP keys
    const allDomains = new Set([
      ...AUTO_PORTALS,
      ...Object.keys(DOMAIN_MAC_MAP)
    ]);

    for (const domain of allDomains) {
      // Check if exists by URL
      const exists = await db.prepare('SELECT id FROM servers WHERE url LIKE ?').bind(`%${domain}%`).first();
      if (!exists) {
        const id = 'sys_' + domain.replace(/\./g, '_').substring(0, 20);
        const url = `http://${domain}:80`;
        const name = "System: " + domain;
        const macs = JSON.stringify(DOMAIN_MAC_MAP[domain] || []);
        await db.prepare('INSERT INTO servers (id,name,url,weight,active,success_count,fail_count,total_requests,avg_response_time,domains,macs) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
          .bind(id, name, url, 9, 1, 0, 0, 0, 0, JSON.stringify([domain]), macs).run();
        serversAdded++;
      }
    }

    // 2. Sync MACs from DOMAIN_MAC_MAP
    for (const [domain, macs] of Object.entries(DOMAIN_MAC_MAP)) {
      const srv = await db.prepare('SELECT id FROM servers WHERE url LIKE ?').bind(`%${domain}%`).first();
      const serverId = srv ? srv.id : '';
      for (const mac of macs) {
        const macExists = await db.prepare('SELECT id FROM macs WHERE mac = ?').bind(mac).first();
        if (!macExists) {
          const id = 'mac_' + Math.random().toString(36).substring(2, 9);
          await db.prepare('INSERT INTO macs (id,mac,weight,active,success_count,fail_count,total_requests,avg_response_time,server_id) VALUES (?,?,?,?,?,?,?,?,?)')
            .bind(id, mac, 10, 1, 0, 0, 0, 0, serverId).run();
          macsAdded++;
        }
      }
    }

    // 3. Sync General MACs from AUTO_MACS
    for (const mac of AUTO_MACS) {
        const macExists = await db.prepare('SELECT id FROM macs WHERE mac = ?').bind(mac).first();
        if (!macExists) {
            const id = 'mac_' + Math.random().toString(36).substring(2, 9);
            await db.prepare('INSERT INTO macs (id,mac,weight,active,success_count,fail_count,total_requests,avg_response_time,server_id) VALUES (?,?,?,?,?,?,?,?,?)')
              .bind(id, mac, 5, 1, 0, 0, 0, 0, '').run();
            macsAdded++;
        }
    }

    return jsonOk({ success: true, message: `تمت المزامنة بنجاح. تم إضافة ${serversAdded} خوادم و ${macsAdded} ماكات جديدة.`, serversAdded, macsAdded }, CORS);
  } catch (e) { return jsonErr(e.message, CORS); }
}

// ============================================================
// دوال البث المباشر
// ============================================================
const _MS = { macs: [], primaryIdx: 0, failed: {}, ts: 0, ttl: 60000 };
const _serverCache = { data: null, ts: 0, ttl: 120000 };
const _settingsCache = { data: null, ts: 0, ttl: 60000 };
const _tokenCache = new Map();
const TOKEN_CACHE_TTL = 60000;

async function loadMacs(db, defaultMacs) {
  const now = Date.now();
  if (_MS.macs.length && (now - _MS.ts) < _MS.ttl) return;
  try {
    let rows;
    if (db) {
      const r = await db.prepare('SELECT mac,weight,active,success_count,fail_count,server_id FROM macs WHERE active=1 ORDER BY weight DESC, success_count DESC').all();
      rows = r.results;
    }
    if (!rows || !rows.length) {
      _MS.macs = defaultMacs.map(m => ({ mac: m, weight: 5, active: true, serverId: '', fails: 0, successes: 0 }));
    } else {
      _MS.macs = rows.map(r => ({ mac: r.mac, weight: r.weight || 5, active: true, serverId: r.server_id || '', fails: r.fail_count || 0, successes: r.success_count || 0 }));
    }
    if (_MS.primaryIdx >= _MS.macs.length) _MS.primaryIdx = 0;
    _MS.ts = now;
  } catch (e) {
    _MS.macs = defaultMacs.map(m => ({ mac: m, weight: 5, active: true, serverId: '', fails: 0, successes: 0 }));
    _MS.primaryIdx = 0; _MS.ts = now;
  }
}

function getPrimaryMac() {
  const now = Date.now();
  const len = _MS.macs.length;
  if (!len) return null;
  for (let i = 0; i < len; i++) {
    const idx = (_MS.primaryIdx + i) % len;
    const m = _MS.macs[idx];
    if (!_MS.failed[m.mac] || now >= _MS.failed[m.mac]) { _MS.primaryIdx = idx; return m.mac; }
  }
  _MS.failed = {}; _MS.primaryIdx = 0;
  return _MS.macs[0]?.mac || null;
}

function getMacList(serverId) {
  const now = Date.now();
  const primary = getPrimaryMac();
  if (!primary) return [];
  const result = [primary];
  for (const m of _MS.macs) {
    if (m.mac === primary) continue;
    if (_MS.failed[m.mac] && now < _MS.failed[m.mac]) continue;
    if (serverId && m.serverId && m.serverId !== serverId) continue;
    result.push(m.mac);
  }
  return result;
}

function onMacSuccess(mac) {
  const idx = _MS.macs.findIndex(m => m.mac === mac);
  if (idx !== -1) { _MS.primaryIdx = idx; _MS.macs[idx].fails = 0; _MS.macs[idx].successes++; }
  delete _MS.failed[mac];
}

function onMacFail(mac) {
  const info = _MS.macs.find(m => m.mac === mac);
  if (info) {
    info.fails = (info.fails || 0) + 1;
    if (info.fails >= 2) {
      _MS.failed[mac] = Date.now() + 60000;
      if (_MS.macs[_MS.primaryIdx]?.mac === mac) _MS.primaryIdx = (_MS.primaryIdx + 1) % _MS.macs.length;
    }
  }
}

async function getAllServers(db) {
  try {
    if (!db) return [];
    const now = Date.now();
    if (_serverCache.data && (now - _serverCache.ts) < _serverCache.ttl) return _serverCache.data;
    const { results } = await db.prepare('SELECT * FROM servers WHERE active=1 ORDER BY weight DESC, success_count DESC').all();
    _serverCache.data = results; _serverCache.ts = now;
    return results;
  } catch (e) { return []; }
}

async function getSettings(db) {
  const now = Date.now();
  if (_settingsCache.data && (now - _settingsCache.ts) < _settingsCache.ttl) return _settingsCache.data;
  try {
    if (!db) return { connectionTimeout: 8000, maxAttempts: 4, bufferSize: 3, cacheEnabled: true };
    const { results } = await db.prepare('SELECT key, value FROM settings').all();
    const s = { connectionTimeout: 8000, maxAttempts: 4, bufferSize: 3, cacheEnabled: true };
    results.forEach(r => { try { s[r.key] = JSON.parse(r.value); } catch (e) { s[r.key] = r.value; } });
    _settingsCache.data = s; _settingsCache.ts = now;
    return s;
  } catch (e) { return { connectionTimeout: 8000, maxAttempts: 4, bufferSize: 3, cacheEnabled: true }; }
}

async function trackTokenUsage(db, token, channelId, clientIp, ctx) {
  if (!db || !token) return 'skip';
  const now = Date.now();
  try {
    let cached = _tokenCache.get(token);
    if (cached && (now - cached.ts) < TOKEN_CACHE_TTL) {
      if (now > cached.expires_at || !cached.is_active) return 'expired';
      if (clientIp && cached.blocked_ips.includes(clientIp)) return 'blocked';
      ctx?.waitUntil?.(db.prepare('UPDATE tokens SET last_used=?,total_usage=total_usage+1,last_channel=?,last_ip=? WHERE token=?').bind(now, channelId, clientIp, token).run());
      return 'ok';
    }
    const row = await db.prepare('SELECT expires_at,is_active,blocked_ips FROM tokens WHERE token=?').bind(token).first();
    if (!row) return 'invalid';
    _tokenCache.set(token, { expires_at: row.expires_at, is_active: row.is_active, blocked_ips: parseJSON(row.blocked_ips, []), ts: now });
    if (now > row.expires_at || !row.is_active) return 'expired';
    const blockedIPs = parseJSON(row.blocked_ips, []);
    if (clientIp && blockedIPs.includes(clientIp)) return 'blocked';
    ctx?.waitUntil?.(db.prepare('UPDATE tokens SET last_used=?,total_usage=total_usage+1,last_channel=?,last_ip=? WHERE token=?').bind(now, channelId, clientIp, token).run());
    return 'ok';
  } catch (e) { return 'skip'; }
}

function invalidateTokenCache(token) {
  if (token) _tokenCache.delete(token);
  else _tokenCache.clear();
}

async function updateMacStats(db, mac, success, responseTime, ctx) {
  if (success) onMacSuccess(mac);
  else onMacFail(mac);
  if (!db || !mac) return;
  try {
    if (success) {
      const sql = 'UPDATE macs SET success_count=success_count+1,total_requests=total_requests+1,avg_response_time=((avg_response_time*(total_requests-1))+?)/NULLIF(total_requests,0),last_used=? WHERE mac=?';
      const promise = db.prepare(sql).bind(responseTime, Date.now(), mac).run();
      if (ctx && ctx.waitUntil) ctx.waitUntil(promise);
      else promise.catch(() => { });
    }
  } catch (e) { }
}

async function getCachedM3U8(cacheKey) {
  try { const c = await caches.open('iptv-m3u8'); return await c.match(cacheKey); } catch (e) { return null; }
}

async function setCachedM3U8(cacheKey, text, workerOrigin, baseUrl) {
  try {
    const c = await caches.open('iptv-m3u8');
    const rewritten = rewriteM3U8(text, baseUrl, workerOrigin);
    const r = new Response(rewritten, { headers: { 'Content-Type': 'application/vnd.apple.mpegurl', 'Cache-Control': 'no-cache, max-age=12', 'Access-Control-Allow-Origin': '*' } });
    await c.put(cacheKey, r.clone());
    return r;
  } catch (e) { return null; }
}

function rewriteM3U8(text, baseUrl, workerOrigin) {
  try {
    const base = new URL(baseUrl);
    const basePath = base.origin + base.pathname.substring(0, base.pathname.lastIndexOf('/') + 1);
    return text.split('\n').map(line => {
      const t = line.trim(); if (!t) return line;
      if (t.startsWith('#EXT-X-KEY') && t.includes('URI="')) return t.replace(/URI="([^"]+)"/, (_, u) => 'URI="' + workerOrigin + '/hls-proxy?url=' + encodeURIComponent(makeAbsolute(u, basePath)) + '"');
      if (t.startsWith('#')) return line;
      return workerOrigin + '/hls-proxy?url=' + encodeURIComponent(makeAbsolute(t, basePath));
    }).join('\n');
  } catch (e) { return text; }
}

function makeAbsolute(uri, basePath) {
  if (uri.startsWith('http')) return uri;
  if (uri.startsWith('/')) { try { return new URL(basePath).origin + uri; } catch (e) { return uri; } }
  return basePath + uri;
}

// ensureServerIdCol function is already defined above

async function apiGetMacPool(db, CORS, defaultMacs) {
  await loadMacs(db, defaultMacs);
  const now = Date.now();
  const primaryMac = getPrimaryMac();
  const pool = _MS.macs.map((m, idx) => ({
    mac: m.mac, weight: m.weight, serverId: m.serverId,
    successCount: m.successes, failCount: m.fails,
    isPrimary: m.mac === primaryMac,
    disabledSec: _MS.failed[m.mac] ? Math.max(0, Math.round((_MS.failed[m.mac] - now) / 1000)) : 0,
    rank: idx + 1
  }));
  return jsonOk({ success: true, data: { macs: pool, primary: primaryMac, total: pool.length } }, CORS);
}

function optimizeForTV(streamUrl, isTV) {
  if (!isTV) return streamUrl;
  try {
    const url = new URL(streamUrl);
    
    // TV optimizations
    url.searchParams.set('bitrate', 'low');
    url.searchParams.set('quality', 'low');
    url.searchParams.set('resolution', '720p');
    url.searchParams.delete('play_token');
    url.searchParams.delete('token');
    
    // Add TV-specific headers simulation
    url.searchParams.set('device', 'tv');
    url.searchParams.set('platform', 'smarttv');
    
    // Force lower bandwidth for TV
    url.searchParams.set('bandwidth', '2000');
    
    return url.toString();
  } catch (e) { 
    // Fallback for malformed URLs
    let result = streamUrl;
    result += (result.includes('?') ? '&' : '?') + 'bitrate=low&quality=low&resolution=720p&device=tv&platform=smarttv&bandwidth=2000';
    return stripPlayToken(result);
  }
}

function stripPlayToken(link) {
  try { 
    const u = new URL(link); 
    u.searchParams.delete('play_token');
    u.searchParams.delete('token');
    u.searchParams.delete('play_token');
    return u.toString(); 
  }
  catch (e) { 
    // Backup regex method for malformed URLs
    return link.replace(/[?&]play_token=[^&]*/g, '').replace(/[?&]token=[^&]*/g, '').replace(/[?&]$/, '').replace('?&', '?');
  }
}

function changeStreamUrl(originalUrl, newDomain = null, newMac = null, newServer = null) {
  try {
    const url = new URL(originalUrl);
    
    // Change domain if provided
    if (newDomain) {
      const hostname = url.hostname;
      url.hostname = newDomain;
    }
    
    // Change MAC if provided
    if (newMac) {
      const macParam = url.searchParams.get('mac');
      if (macParam) {
        url.searchParams.set('mac', newMac);
      }
    }
    
    // Change server if provided (change the entire origin)
    if (newServer) {
      const serverUrl = new URL(newServer);
      url.protocol = serverUrl.protocol;
      url.hostname = serverUrl.hostname;
      url.port = serverUrl.port;
    }
    
    // Always strip play_token
    url.searchParams.delete('play_token');
    url.searchParams.delete('token');
    
    return url.toString();
  } catch (e) {
    // Fallback for malformed URLs
    let result = originalUrl;
    if (newMac) {
      result = result.replace(/mac=[^&]*/, 'mac=' + encodeURIComponent(newMac));
    }
    if (newDomain) {
      result = result.replace(/https?:\/\/[^\/]+/, 'https://' + newDomain);
    }
    return stripPlayToken(result);
  }
}

async function tryAllLinks(domains, servers, macs, isTVDevice) {
  const failedCombinations = new Set();
  const maxAttempts = Math.min(domains.length * servers.length * macs.length, 50);
  let attempts = 0;
  
  // Create all possible combinations with priority
  const combinations = [];
  for (let d = 0; d < domains.length; d++) {
    for (let s = 0; s < servers.length; s++) {
      for (let m = 0; m < macs.length; m++) {
        combinations.push({
          domain: domains[d],
          server: servers[s],
          mac: macs[m],
          priority: m === 0 ? 1 : 2, // First MAC has higher priority
          serverPriority: s === 0 ? 1 : 2 // First server has higher priority
        });
      }
    }
  }
  
  // Sort by priority (first MAC, first server)
  combinations.sort((a, b) => {
    if (a.priority !== b.priority) return a.priority - b.priority;
    return a.serverPriority - b.serverPriority;
  });
  
  for (const combo of combinations) {
    if (attempts >= maxAttempts) break;
    
    const comboKey = `${combo.domain}:${combo.server}:${combo.mac}`;
    if (failedCombinations.has(comboKey)) continue;
    
    let testUrl = combo.server.replace('{domain}', combo.domain).replace('{mac}', combo.mac);
    testUrl = stripPlayToken(testUrl);
    testUrl = optimizeForTV(testUrl, isTVDevice);
    
    try {
      const resp = await fetch(testUrl, { 
        method: "GET", 
        signal: AbortSignal.timeout(2000),
        headers: {
          'Range': 'bytes=0-1024',
          'User-Agent': isTVDevice ? 'SmartTV/1.0' : 'Mozilla/5.0',
          'Accept': '*/*'
        }
      });
      
      if (resp.ok) {
        return testUrl;
      } else {
        failedCombinations.add(comboKey);
      }
    } catch (e) {
      failedCombinations.add(comboKey);
      continue;
    }
    
    attempts++;
  }
  
  return null;
}

async function handleLiveStreamAdvanced(request, db, CORS) {
  const url = new URL(request.url);
  const channelId = url.searchParams.get('id');
  const isTVDevice = /SmartTV|Android TV/i.test(request.headers.get('User-Agent'));
  if (!channelId) return new Response('Channel ID required', { status: 400, headers: CORS });
  try {
    let channelData = null;

    const packages = await db.prepare('SELECT channels FROM packages').all();

    for (const pkg of packages.results || []) {
      const channels = parseJSON(pkg.channels, []);
      const ch = channels.find(c => c.id === channelId);
      if (ch) {
        channelData = ch;
        break;
      }
    }

    if (!channelData)
      return new Response('Channel not found', { status: 404, headers: CORS });
    
    // Get channel domains and macs
    let domains = channelData.domains || [];
    let macs = channelData.macs || [];
    
    // Get all servers with their domains
    const servers = await getAllServers(db);
    let allDomains = [...domains];
    let allServerUrls = [channelData.url];
    
    // Add server domains if channel doesn't have domains
    if (domains.length === 0 && servers.length > 0) {
      servers.forEach(server => {
        if (server.domains && server.domains.length > 0) {
          allDomains = [...allDomains, ...server.domains];
        }
        allServerUrls.push(server.url);
      });
    }
    
    // Fallback to default if no domains
    if (allDomains.length === 0) {
      allDomains = getAllDomains();
    }
    
    // Use channel macs or default
    if (macs.length === 0) {
      macs = ['00:1A:79:0D:20:AA'];
    }
    
    const finalUrl = await tryAllLinks(allDomains, allServerUrls, macs, isTVDevice);
    if (!finalUrl) return new Response('All servers failed', { status: 502, headers: CORS });
    return new Response(JSON.stringify({ stream: finalUrl }), { status: 200, headers: CORS });
  } catch (e) { return new Response('Stream Error: ' + e.message, { status: 500, headers: CORS }); }
}

async function handleLiveStream(request, url, db, CORS, mainServer, defaultMacs, ctx, env, isTV) {
  try {
    const fileName = (url.pathname.split('/')[2] || '');
    const channelId = fileName.split('.')[0];
    const extension = fileName.split('.')[1] || 'ts';
    const token = url.searchParams.get('token');
    const clientIp = request.headers.get('CF-Connecting-IP') || '';
    const ua = request.headers.get('User-Agent') || '';
    const isTVDevice = isTV || /SMART-TV|WebTV|SmartTV|LGTV|TV/i.test(ua);

    const now2 = Date.now();
    if (!G_SETTINGS || now2 - G_STIME > 300000) { G_SETTINGS = await getSettings(db); G_STIME = now2; }
    const settings = G_SETTINGS;
    if (!G_SERVERS || now2 - G_SRVTIME > 120000) { G_SERVERS = await getAllServers(db); G_SRVTIME = now2; }
    const activeServers = G_SERVERS.length ? G_SERVERS : [{ id: 'main', url: mainServer, weight: 1 }];

    let tokStatus = G_TOKENS.get(token);
    if (!tokStatus || now2 - tokStatus.checkedAt > 60000) {
      const row = await db.prepare('SELECT * FROM tokens WHERE token = ?').bind(token).first();
      tokStatus = { checkedAt: now2, status: row && row.is_active && now2 < row.expires_at ? 'ok' : 'blocked', row };
      G_TOKENS.set(token, tokStatus);
    }
    if (token && tokStatus.status !== 'ok') return new Response('Unauthorized/Expired', { status: 403, headers: CORS });
    if (token && db) ctx.waitUntil(trackTokenUsage(db, token, channelId, clientIp, ctx));

    const allPairs = [];
    
    // Get channel info for domains and macs
    let channelDomains = [];
    let channelMacs = [];
    
    if (db) {
      try {
        const pkgsResponse = await db.prepare('SELECT channels FROM packages').all();
        for (const pkg of pkgsResponse.results || []) {
          const chs = parseJSON(pkg.channels, []);
          const ch = chs.find(c => c.id === channelId);
          if (ch) {
            channelDomains = ch.domains || [];
            channelMacs = ch.macs || [];
            break;
          }
        }
      } catch (e) { }
    }
    
    // Use channel domains or server domains
    for (const server of activeServers) {
      const serverMacs = getMacList(server.id);
      let domainsToUse = channelDomains.length > 0 ? channelDomains : (server.domains || []);
      let macsToUse = channelMacs.length > 0 ? channelMacs : serverMacs;
      
      for (const m of macsToUse) {
        for (const d of domainsToUse) {
          allPairs.push({ 
            serverUrl: server.url.replace('{domain}', d), 
            mac: m, 
            serverId: server.id,
            domain: d 
          });
        }
      }
    }
    
    if (!allPairs.length) {
      for (const [domain, macs] of Object.entries(DOMAIN_MAC_MAP)) {
        for (const mac of macs) {
          allPairs.push({ serverUrl: `http://${domain}:80`, mac: mac, serverId: 'map', domain: domain });
        }
      }
    }

    const cacheId = channelId + ':' + (isTVDevice ? 'tv' : 'std');
    let result = null;

    if (extension === 'm3u8' && settings.cacheEnabled !== false) {
      const m3u8Key = new Request(url.origin + '/m3u8-cache/' + channelId);
      const cachedPl = await getCachedM3U8(m3u8Key);
      if (cachedPl) { const h = new Headers(cachedPl.headers); h.set('X-Ultra-Cache', 'hit'); return new Response(cachedPl.body, { status: cachedPl.status, headers: h }); }
    }

    await loadMacs(db, defaultMacs);

    const raceTimeout = 3500;
    const fastTimeout = 3500;

    let cachedValue = ultraMacGet(cacheId) || serverMacCache.get(cacheId) || null;
    let cachedPair = null;
    if (cachedValue) { try { cachedPair = JSON.parse(cachedValue); } catch (e) { const srv = activeServers[0]; cachedPair = { mac: cachedValue, serverUrl: srv.url, serverId: srv.id }; } }

    if (!cachedPair && env.PACKAGES_KV) {
      try {
        const kv = await Promise.race([env.PACKAGES_KV.get(cacheId), new Promise(r => setTimeout(() => r(null), 80))]);
        if (kv) cachedPair = JSON.parse(kv);
      } catch (e) { }
    }

    if (cachedPair) {
      result = await trySinglePair(cachedPair, channelId, extension, fastTimeout, db, isTVDevice, ctx);
      if (!result) { ultraMacCache.delete(cacheId); serverMacCache.delete(cacheId); }
    }

    if (!result) {
      const racePool = allPairs.filter(p => !cachedPair || p.mac !== cachedPair.mac || p.serverUrl !== cachedPair.serverUrl).slice(0, 8);
      if (racePool.length > 0) result = await raceConnections(racePool, channelId, extension, raceTimeout, db, isTVDevice, ctx);
      if (!result) { _MS.failed = {}; result = await raceConnections(allPairs.slice(0, 12), channelId, extension, raceTimeout + 1000, db, isTVDevice, ctx); }
    }

    if (result && result.mac) {
      const saveValue = JSON.stringify({ mac: result.mac, serverUrl: result.serverUrl, serverId: result.serverId });
      ultraMacSet(cacheId, saveValue);
      serverMacCacheSet(cacheId, saveValue);
      if (env.PACKAGES_KV) ctx.waitUntil(env.PACKAGES_KV.put(cacheId, saveValue, { expirationTtl: extension === 'ts' ? 900 : 3600 }));
    }

    if (!result) return new Response('No available source', { status: 503, headers: CORS });

    if (extension === 'm3u8' && result.resp) {
      const m3u8Key = new Request(url.origin + '/m3u8-cache/' + channelId);
      try {
        const text = await result.resp.text();
        const saved = await setCachedM3U8(m3u8Key, text, url.origin, result.serverUrl);
        if (saved) { const fh = new Headers(saved.headers); fh.set('X-Used-MAC', result.mac); return new Response(saved.body, { status: 200, headers: fh }); }
        const rewritten = rewriteM3U8(text, result.serverUrl, url.origin);
        return new Response(rewritten, { status: 200, headers: new Headers({ 'Content-Type': 'application/vnd.apple.mpegurl', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'public, max-age=120', 'X-Used-MAC': result.mac }) });
      } catch (e) { }
    }

    return new Response(result.resp.body, {
      status: 200,
      headers: new Headers({ 'Access-Control-Allow-Origin': '*', 'Content-Type': extension === 'm3u8' ? 'application/vnd.apple.mpegurl' : 'video/mp2t', 'X-Used-MAC': result.mac, 'Cache-Control': 'no-cache, no-store, must-revalidate', 'X-Accel-Buffering': 'no', 'Pragma': 'no-cache' })
    });
  } catch (e) { return new Response('Stream Error: ' + e.message, { status: 500, headers: CORS }); }
}

function generatePlaylistUrl(baseUrl, channelId, extension, token, domain = null) {
  let url = baseUrl + '/live/' + channelId + '.' + extension;
  if (token) {
    url += '?token=' + encodeURIComponent(token);
  }
  if (domain && baseUrl.includes('{domain}')) {
    url = url.replace('{domain}', domain);
  }
  return url;
}

function generateSmartPlaylistUrl(channelId, extension, token, domains = [], servers = []) {
  // If we have servers and domains, use them
  if (servers.length > 0 && domains.length > 0) {
    // Try first server with first domain
    const server = servers[0];
    const domain = domains[0];
    const serverUrl = server.url.replace('{domain}', domain);
    return '/live/' + channelId + '.' + extension + '?token=' + encodeURIComponent(token);
  }
  
  // Fallback to standard URL
  return '/live/' + channelId + '.' + extension + (token ? '?token=' + encodeURIComponent(token) : '');
}

// ============================================================
// API السباق
// ============================================================
async function raceConnections(
  pairs,
  channelId,
  extension,
  timeout,
  db,
  isTVDevice,
  ctx
) {

  if (!pairs || pairs.length === 0) return null;

  const s = G_SETTINGS || { 
    racePoolSize: 3, 
    raceTimeout: 3500, 
    fallbackTimeout: 800, 
    retryCount: 2, 
    retryDelay: 1200, 
    keepAliveTimeout: 5 
  };

  const controllers = [];

  async function racePool(pool, poolTimeout) {
    const tasks = pool.map(pair => (async () => {
      const { serverUrl, mac, serverId } = pair;
      const streamUrl = await buildStream(serverUrl, mac, channelId);
      if (!streamUrl) throw new Error('فشل تسجيل الدخول');
      
      const controller = new AbortController();
      controllers.push(controller);
      const timer = setTimeout(() => controller.abort(), poolTimeout);

      const headers = { 
        "User-Agent": "MAG200 stbapp ver: 2 rev: 250 Safari/533.3",
        "X-User-Agent": "Model: MAG250; SH: 1",
        "X-STB-MAC": mac,
        "Accept": "*/*",
        "Connection": "keep-alive",
        "Cache-Control": "no-cache",
        "Referer": serverUrl + "/c/"
      };

      const resp = await fetch(streamUrl, {
        headers,
        signal: controller.signal
      }).catch(e => {
        if (e.name === 'AbortError') throw new Error('Timeout');
        throw new Error('Network Error');
      });
      
      if (resp.ok) {
        clearTimeout(timer);
        return { resp, mac, serverUrl, serverId, controller };
      }
      if (resp.status === 458 || resp.status === 429) {
        // Rate limit hit, mark as blocked temporarily
        MAC_FAIL.set(serverUrl + mac, Date.now());
        throw new Error('Rate Limited (458/429)');
      }
      if (resp.status === 456 || resp.status === 403) {
        // Mark MAC as temporarily blocked for this server
        MAC_FAIL.set(serverUrl + mac, Date.now());
        throw new Error('Blocked (456/403)');
      }
      throw new Error(`Error ${resp.status}`);
    })());

    return await Promise.any(tasks).catch((e) => {
      if (e instanceof AggregateError) {
         // Return the first meaningful error
         const msg = e.errors.find(err => err && err.message !== 'x' && !err.message.includes('Timeout'))?.message || e.errors[0]?.message || 'فشل مجهول';
         return { error: msg };
      }
      return { error: 'لا توجد سيرفرات' };
    });
  }

  // Race based on dynamic settings
  const poolSize = s.racePoolSize || 6;
  const firstTimeout = timeout || s.raceTimeout || 3500;
  const secondTimeout = s.fallbackTimeout || 800;

  let winner = await racePool(pairs.slice(0, poolSize), firstTimeout);
  let finalError = winner?.error;
  
  if (winner && winner.error && pairs.length > poolSize) {
    // FALLBACK: try remaining pairs
    const secondWinner = await racePool(pairs.slice(poolSize, poolSize + 10), secondTimeout);
    winner = secondWinner;
    if (secondWinner && secondWinner.error) finalError = secondWinner.error;
  }

  // Clean up all losers
  for (const c of controllers) {
    if (!winner || c !== winner.controller) {
      c.abort();
    }
  }

  if (winner && !winner.error) {
    return { resp: winner.resp, mac: winner.mac, serverUrl: winner.serverUrl, serverId: winner.serverId };
  }

  return { error: finalError || 'لا توجد خوادم متاحة' };
}

async function trySinglePair(pair, channelId, extension, timeout, db, isTVDevice, ctx, controller = new AbortController()) {
  if (!pair || !pair.mac || !pair.serverUrl) throw new Error('Invalid pair');
  const { mac, serverUrl, serverId } = pair;
  const t0 = Date.now();
  
  try {
    const streamUrl = await buildStream(serverUrl, mac, channelId);
    if (!streamUrl) throw new Error('Build stream failed');

    const resp = await fetch(streamUrl, { 
      headers: { 'User-Agent': 'Mozilla/5.0', 'Referer': serverUrl + '/', 'Accept': '*/*' }, 
      redirect: 'follow', 
      signal: controller.signal,
      keepalive: true
    });

    if (!resp.ok) { 
      updateMacStats(db, mac, false, 0, ctx); 
      throw new Error('Response not ok'); 
    }
    
    updateMacStats(db, mac, true, Date.now() - t0, ctx);
    return { resp, mac, serverUrl, serverId };
  } catch (e) { 
    updateMacStats(db, mac, false, 0, ctx); 
    throw e; 
  }
}



// ============================================================
// ============================================================
// Ultra Fast HLS Proxy V5
// ============================================================

const _hlsCache = new Map()

async function handleHLSProxy(request, url, CORS) {
  try {
    const targetUrl = decodeURIComponent(url.searchParams.get('url') || '');
    
    if (!targetUrl)
      return new Response('Missing url', { status: 400, headers: CORS });

    // Cache hit
    if(_hlsCache.has(targetUrl)){
      return _hlsCache.get(targetUrl)
    }

    // timeout controller
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const resp = await fetch(targetUrl, {
      headers: {
        'User-Agent':'Mozilla/5.0',
        'Referer': new URL(targetUrl).origin + '/',
        'Accept':'*/*'
      },
      redirect:'follow',
      signal:controller.signal,
      cf:{
        cacheTtl:30,
        cacheEverything:true
      }
    });

    clearTimeout(timeout);

    if (!resp.ok)
      return new Response('Upstream ' + resp.status, { status: resp.status, headers: CORS });

    const ct = resp.headers.get('content-type') || '';
    const headers = new Headers({
      'Access-Control-Allow-Origin':'*',
      'Accept-Ranges':'bytes',
      'X-Accel-Buffering':'no',
      'Cache-Control':'public, max-age=30'
    });

    // ============================
    // M3U8
    // ============================
    if (ct.includes('mpegurl') || targetUrl.includes('.m3u8')) {
      headers.set('Content-Type', 'application/vnd.apple.mpegurl');
      
      const text = await resp.text();
      const body = rewriteM3U8(text, targetUrl, new URL(request.url).origin);
      
      const response = new Response(body, { status:200, headers });

      // cache
      _hlsCache.set(targetUrl, response.clone());
      setTimeout(() => _hlsCache.delete(targetUrl), 15000);

      return response;
    }

    // ============================
    // TS STREAM
    // ============================
    headers.set('Content-Type', 'video/mp2t');
    return new Response(resp.body, { status: resp.status, headers });
  } catch(e) {
    return new Response('Proxy error: ' + e.message, { status:500, headers:CORS });
  }
}

// ============================================================
// قائمة التشغيل
// ============================================================
const playlistCache = new Map()

async function handlePlaylist(url, db, CORS) {
  try {
    const token = url.searchParams.get('token');
    const format = url.searchParams.get('format') || 'ts';
    
    // Check cache first (TTL 30 seconds)
    const cachedEntry = playlistCache.get(token);
    if (cachedEntry && (Date.now() - cachedEntry.ts < 30000)) {
      return cachedEntry.response.clone();
    }
    
    if (!token || !db) {
      let playlist = '#EXTM3U x-tvg-url="" cache="500"\n';
      playlist += '#EXTINF:-1 tvg-id="1" tvg-name="Test Channel" tvg-logo="" group-title="Test",Test Channel\n';
      playlist += url.origin + '/live/1.ts\n';
      return new Response(playlist, { headers: { 'Content-Type': 'application/x-mpegurl; charset=utf-8', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-cache, no-store' } });
    }
    const row = await db.prepare('SELECT * FROM tokens WHERE token = ?').bind(token).first();
    if (!row) return new Response('Token not found', { status: 403, headers: CORS });
    const now = Date.now();
    if (now > row.expires_at || !row.is_active) return new Response('Token expired', { status: 403, headers: CORS });
    const packages = parseJSON(row.packages_order || row.packages, []);
    const ext = format === 'm3u8' ? 'm3u8' : 'ts';
    const isNetlink = format === 'netlink';
    let playlist = isNetlink ? '#EXTM3U\n' : '#EXTM3U x-tvg-url="" cache="500"\n';
    const pkgMap = {};
    if (packages.length > 0) {
      const placeholders = packages.map(() => '?').join(',');
      const pkgRows = await db.prepare('SELECT * FROM packages WHERE id IN (' + placeholders + ')').bind(...packages).all();
      for (const p of (pkgRows.results || [])) pkgMap[p.id] = p;
    }
    for (const pkgId of packages) {
      const pkg = pkgMap[pkgId];
      if (!pkg) continue;
      const channels = parseJSON(pkg.channels, []);
      for (const ch of channels) {
        const logo = ch.logo || '';
        const group = (ch.group || pkg.name || '').replace(/"/g, '');
        const name = (ch.name || '').replace(/,/g, ' ');
        if (isNetlink) {
          playlist += '#EXTINF:-1,' + name + '\n';
          const smartUrl = generateSmartPlaylistUrl(ch.id, 'ts', token, [], []);
          playlist += url.origin + smartUrl + '\n';
        } else {
          playlist += '#EXTINF:-1 tvg-id="' + ch.id + '" tvg-name="' + name + '"' + (logo ? ' tvg-logo="' + logo + '"' : '') + ' group-title="' + group + '",' + name + '\n';
          const smartUrl = generateSmartPlaylistUrl(ch.id, ext, token, [], []);
          playlist += url.origin + smartUrl + '\n';
        }
      }
    }
    
    const response = new Response(playlist, { headers: { 'Content-Type': isNetlink ? 'text/plain; charset=utf-8' : 'application/x-mpegurl; charset=utf-8', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'public, max-age=300' } });
    
    // Store in cache with timestamp
    playlistCache.set(token, { response: response.clone(), ts: Date.now() });
    
    return response;
  } catch (e) { return new Response('Error: ' + e.message, { status: 500, headers: CORS }); }
}

// ============================================================
// وكيل EPG
// ============================================================
let epgCache = null
let epgTime = 0

async function handleEPGProxy(CORS) {
  try {
    const now = Date.now()

    if (epgCache && (now - epgTime < 21600000)) {
      return new Response(epgCache, {
        headers: {
          'Content-Type': 'application/xml',
          'Cache-Control': 'public,max-age=21600',
          'Access-Control-Allow-Origin': '*'
        }
      })
    }

    const resp = await fetch('https://raw.githubusercontent.com/tahardsp31/epg/main/epg.xml', {
      cf: {
        cacheTtl: 21600,
        cacheEverything: true
      }
    })

    const xml = await resp.text()

    epgCache = xml
    epgTime = now

    return new Response(xml, {
      headers: {
        'Content-Type': 'application/xml',
        'Cache-Control': 'public,max-age=21600',
        'Access-Control-Allow-Origin': '*'
      }
    })
  } catch (e) {
    return new Response('EPG Error: ' + e.message, {
      status: 500,
      headers: CORS
    })
  }
}

// ============================================================
// لوحة التحكم الرئيسية
// ============================================================
function renderPanel(url, env, CORS, defaultMacs, isTV) {
  const W = url.origin;
  const html = buildHTML(W, isTV);
  return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store, no-cache, must-revalidate', 'Access-Control-Allow-Origin': '*' }, status: 200 });
}

function buildHTML(W, isTV) {
  const tvOpt = isTV ? '<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no"><style>body{font-size:18px}.btn{padding:12px 24px;font-size:1.1rem}</style>' : '';
  const NL = String.fromCharCode(10);
  const allowed = JSON.stringify(Array.from(new Set([...AUTO_PORTALS, ...Object.keys(DOMAIN_MAC_MAP)])));
  const parts = [];
  parts.push(`<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0">
<title>Venom IPTV Panel</title>
${tvOpt}
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--p:#2563eb;--s:#7c3aed;--ok:#059669;--err:#dc2626;--warn:#d97706;--dark:#0f172a;--darker:#020617;--light:#f1f5f9;--gray:#334155}
body{font-family:'Segoe UI',sans-serif;background:linear-gradient(135deg,var(--dark),var(--darker));color:var(--light);min-height:100vh}
#overlay{position:fixed;inset:0;background:#0f172a;display:flex;align-items:center;justify-content:center;z-index:9999}
.lbox{width:90%;max-width:420px;background:rgba(15,23,42,.97);border:2px solid var(--p);border-radius:24px;padding:40px 30px;box-shadow:0 25px 50px -12px rgba(37,99,235,.5)}
.linp{width:100%;padding:14px;margin-bottom:15px;background:rgba(15,23,42,.8);border:2px solid var(--gray);border-radius:12px;color:#fff;font-size:1rem;outline:none}
.linp:focus{border-color:var(--p)}
.lbtn{width:100%;padding:14px;background:linear-gradient(135deg,var(--p),var(--s));color:#fff;border:none;border-radius:12px;font-size:1.1rem;font-weight:700;cursor:pointer}
.lerr{background:rgba(220,38,38,.15);border:1px solid var(--err);color:#fca5a5;padding:10px;border-radius:8px;margin-bottom:15px;display:none;text-align:center}
#app{display:none}
.topbar{background:rgba(15,23,42,.95);border:2px solid var(--p);border-radius:14px;padding:14px 22px;margin:16px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px}
.tabs{display:flex;gap:8px;flex-wrap:wrap;margin:0 16px 16px}
.tab{padding:9px 16px;background:rgba(15,23,42,.9);border:2px solid var(--p);border-radius:9px;color:var(--light);cursor:pointer;font-weight:600;font-size:.9rem;display:flex;align-items:center;gap:6px}
.tab:hover{background:rgba(37,99,235,.2)}
.tab.on{background:linear-gradient(135deg,var(--p),var(--s));color:#fff}
.sec{display:none}.sec.on{display:block}
.container{max-width:1400px;margin:0 auto;padding:0 16px}
.card{background:rgba(15,23,42,.95);border:2px solid var(--p);border-radius:18px;padding:18px;margin-bottom:18px}
.cardh{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;padding-bottom:10px;border-bottom:2px solid var(--p);flex-wrap:wrap;gap:8px}
.cardh h3{color:#fff;font-size:1.1rem;display:flex;align-items:center;gap:8px}
.sgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:20px}
.scard{background:rgba(15,23,42,.9);border:2px solid var(--p);border-radius:16px;padding:16px;display:flex;align-items:center;gap:12px}
.sico{width:44px;height:44px;background:linear-gradient(135deg,var(--p),var(--s));border-radius:10px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.sico i{font-size:1.3rem;color:#fff}
.sval{font-size:1.7rem;font-weight:700;color:#fff}
.slbl{color:#94a3b8;font-size:.85rem}
.btn{padding:9px 18px;border:none;border-radius:9px;font-size:.9rem;font-weight:600;cursor:pointer;display:inline-flex;align-items:center;gap:7px;transition:all .2s}
.btn:hover{transform:translateY(-1px);opacity:.9}
.bp{background:linear-gradient(135deg,var(--p),var(--s));color:#fff}
.bg{background:linear-gradient(135deg,var(--ok),#047857);color:#fff}
.br{background:linear-gradient(135deg,var(--err),#b91c1c);color:#fff}
.bi{background:linear-gradient(135deg,#0891b2,#0e7490);color:#fff}
.bw{background:linear-gradient(135deg,var(--warn),#b45309);color:#fff}
.bs{background:linear-gradient(135deg,#059669,#047857);color:#fff}
.bsm{padding:6px 11px;font-size:.82rem}
table{width:100%;border-collapse:collapse}
th{background:rgba(37,99,235,.2);padding:11px;text-align:right;border-bottom:2px solid var(--p);color:#fff;font-size:.9rem}
td{padding:9px 11px;border-bottom:1px solid var(--gray);font-size:.9rem}
tr:hover{background:rgba(37,99,235,.08)}
.fg{margin-bottom:13px}
.fg label{display:block;margin-bottom:5px;color:var(--light);font-weight:600;font-size:.9rem}
.fc{width:100%;padding:10px;background:rgba(15,23,42,.8);border:2px solid var(--gray);border-radius:8px;color:#fff;font-size:.95rem;outline:none}
.fc:focus{border-color:var(--p)}
.fr{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.badge{display:inline-block;padding:3px 8px;border-radius:10px;font-size:.78rem;font-weight:600}
.badge-ok{background:rgba(5,150,105,.2);color:#4ade80;border:1px solid var(--ok)}
.badge-err{background:rgba(220,38,38,.2);color:#f87171;border:1px solid var(--err)}
.badge-warn{background:rgba(217,119,6,.2);color:#fbbf24;border:1px solid var(--warn)}
.badge-info{background:rgba(37,99,235,.2);color:#60a5fa;border:1px solid var(--p)}
.modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.8);align-items:center;justify-content:center;z-index:2000}
.modal.on{display:flex}
.mbox{background:rgba(15,23,42,.98);border:2px solid var(--p);border-radius:18px;padding:22px;max-width:550px;width:90%;max-height:90vh;overflow-y:auto}
.mh{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;padding-bottom:10px;border-bottom:2px solid var(--p)}
.mh h3{color:#fff}
.mcl{font-size:1.8rem;color:#94a3b8;cursor:pointer;line-height:1}
.mcl:hover{color:var(--err)}
.macitem{background:rgba(37,99,235,.08);border:1px solid var(--p);border-radius:8px;padding:10px;display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;flex-wrap:wrap;gap:8px}
.sortitem{background:rgba(15,23,42,.8);border:1px solid var(--p);border-radius:7px;padding:9px 12px;margin-bottom:5px;display:flex;align-items:center;gap:10px}
.sortitem:hover{background:rgba(37,99,235,.15)}
.grip{cursor:grab;color:#94a3b8}
.pkgcard{background:rgba(15,23,42,.8);border:2px solid var(--p);border-radius:12px;padding:14px;transition:all .2s;cursor:grab}
.pkgcard:hover{border-color:var(--s);background:rgba(37,99,235,.15)}
.pkgcard-ghost{opacity:.5;border-style:dashed}
.pkggrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:18px}
.urlbox{background:rgba(15,23,42,.8);border:2px solid var(--p);border-radius:8px;padding:10px 80px 10px 10px;direction:ltr;text-align:left;font-family:monospace;word-break:break-all;position:relative;min-height:40px;font-size:.88rem}
.cpbtn{position:absolute;left:8px;top:7px;background:var(--p);color:#fff;border:none;border-radius:5px;padding:3px 8px;cursor:pointer;font-size:.78rem}
.uparea{border:3px dashed var(--p);border-radius:14px;padding:28px;text-align:center;cursor:pointer;background:rgba(37,99,235,.04)}
.uparea i{font-size:2.8rem;color:var(--p);display:block;margin-bottom:8px}
.iperr{background:rgba(220,38,38,.08);border:1px solid var(--err);border-radius:6px;padding:8px;margin-bottom:5px;display:flex;justify-content:space-between;align-items:center}
.tbox{background:rgba(37,99,235,.08);border:1px solid var(--p);border-radius:10px;padding:14px;margin:8px 0}
.tstats{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-top:10px}
.tstat{background:rgba(0,0,0,.3);padding:10px;border-radius:8px;text-align:center}
.tstatv{font-size:1.3rem;font-weight:700;color:#60a5fa}
.tstatl{font-size:.78rem;color:#94a3b8}
.uhist{max-height:180px;overflow-y:auto}
.uitem{background:rgba(0,0,0,.25);padding:7px;border-radius:6px;margin-bottom:4px;font-size:.82rem;display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.ptag{display:inline-block;padding:2px 7px;background:rgba(37,99,235,.2);border-radius:10px;margin:2px;font-size:.78rem;color:#60a5fa}
.pkg-sort-list{max-height:280px;overflow-y:auto;background:rgba(0,0,0,.3);border-radius:12px;padding:10px;border:1.5px solid #334155}
.pkg-sort-item{background:#1e293b;margin:6px 0;padding:10px 14px;border-radius:9px;display:flex;align-items:center;gap:12px;cursor:grab;border:1px solid transparent;transition:all .2s}
.pkg-sort-item:hover{border-color:#2563eb;background:#243347}
.pkg-sort-item input[type=checkbox]{width:20px;height:20px;cursor:pointer}
@media(max-width:768px){.fr{grid-template-columns:1fr}.topbar{flex-direction:column;text-align:center}.sgrid{grid-template-columns:1fr 1fr}}
</style>
</head>
<body>
<div id="overlay">
  <div class="lbox">
    <div style="text-align:center;margin-bottom:24px">
      <i class="fas fa-satellite-dish" style="font-size:3.5rem;color:var(--p);background:rgba(37,99,235,.15);padding:18px;border-radius:50%"></i>
      <h2 style="color:#fff;margin-top:14px;font-size:1.8rem">Venom IPTV</h2>
      <p style="color:#94a3b8">لوحة التحكم المتطورة</p>
    </div>
    <div id="lerr" class="lerr"><i class="fas fa-exclamation-circle"></i> بيانات الدخول غير صحيحة</div>
    <input type="text" id="lu" class="linp" placeholder="اسم المستخدم" value="admin">
    <input type="password" id="lp" class="linp" placeholder="كلمة المرور" value="admin123">
    <button class="lbtn" onclick="doLogin()"><i class="fas fa-sign-in-alt"></i> دخول</button>
    <div style="background:rgba(37,99,235,.1);border-radius:8px;padding:10px;margin-top:14px;text-align:center">
      <small style="color:#94a3b8">admin / admin123</small>
    </div>
    <button onclick="window.open('/api/debug','_blank')" style="width:100%;margin-top:10px;padding:8px;background:rgba(37,99,235,.15);border:1px solid var(--p);border-radius:8px;color:#94a3b8;cursor:pointer;font-size:.8rem">
      <i class="fas fa-bug"></i> تشخيص DB
    </button>
  </div>
</div>

<div id="app">
  <div class="topbar">
    <div style="display:flex;align-items:center;gap:12px">
      <i class="fas fa-satellite-dish" style="font-size:1.8rem;color:var(--p)"></i>
      <h2 id="ptitle" style="color:#fff;font-size:1.3rem">الرئيسية</h2>
    </div>
    <div style="display:flex;gap:8px">
      <button class="btn bi bsm" onclick="loadData()"><i class="fas fa-sync-alt"></i> تحديث</button>
      <button class="btn br bsm" onclick="doLogout()"><i class="fas fa-sign-out-alt"></i> خروج</button>
    </div>
  </div>

  <div class="container">
    <div class="tabs">
      <div class="tab on" onclick="showTab('dash',this)"><i class="fas fa-home"></i> الرئيسية</div>
      <div class="tab" onclick="showTab('tokens',this)"><i class="fas fa-key"></i> التوكنات</div>
      <div class="tab" onclick="showTab('macs',this)"><i class="fas fa-network-wired"></i> MACs</div>
      <div class="tab" onclick="showTab('packages',this)"><i class="fas fa-box"></i> الباقات</div>
      <div class="tab" onclick="showTab('channels',this)"><i class="fas fa-tv"></i> القنوات</div>
      <div class="tab" onclick="showTab('playlist',this)"><i class="fas fa-file-code"></i> M3U</div>
      <div class="tab" onclick="showTab('import',this)"><i class="fas fa-upload"></i> رفع M3U</div>
      <div class="tab" onclick="showTab('servers',this)"><i class="fas fa-server"></i> الخوادم</div>
      <div class="tab" onclick="showTab('adv-settings',this)"><i class="fas fa-tools"></i> الإعدادات المتقدمة</div>
    </div>

    <div class="sec on" id="s-dash">
      <div class="sgrid">
        <div class="scard"><div class="sico"><i class="fas fa-key"></i></div><div><div class="sval" id="st-tokens">0</div><div class="slbl">التوكنات</div></div></div>
        <div class="scard"><div class="sico"><i class="fas fa-check-circle"></i></div><div><div class="sval" id="st-active">0</div><div class="slbl">نشطة</div></div></div>
        <div class="scard"><div class="sico"><i class="fas fa-network-wired"></i></div><div><div class="sval" id="st-macs">0</div><div class="slbl">MACs</div></div></div>
        <div class="scard"><div class="sico"><i class="fas fa-box"></i></div><div><div class="sval" id="st-pkgs">0</div><div class="slbl">الباقات</div></div></div>
        <div class="scard"><div class="sico"><i class="fas fa-tv"></i></div><div><div class="sval" id="st-chs">0</div><div class="slbl">القنوات</div></div></div>
        <div class="scard"><div class="sico"><i class="fas fa-server"></i></div><div><div class="sval" id="st-srv">0</div><div class="slbl">الخوادم</div></div></div>
        <div class="scard" style="background:linear-gradient(135deg,#7c3aed,#2563eb)"><div class="sico"><i class="fas fa-bolt"></i></div><div><div class="sval" id="st-active-sessions">0</div><div class="slbl">روابط نشطة</div></div></div>
        <div class="scard" style="border:1px solid #f87171"><div class="sico"><i class="fas fa-exclamation-triangle" style="color:#f87171"></i></div><div><div class="sval" id="st-fails" style="color:#f87171">0</div><div class="slbl">أخطاء حالية</div></div></div>
      </div>
        <div class="cardh">
          <h3><i class="fas fa-satellite"></i> الروابط النشطة حالياً</h3>
          <button class="btn br bsm" onclick="clearSessions()"><i class="fas fa-trash-alt"></i> مسح جميع الروابط</button>
        </div>
        <div style="overflow-x:auto">
          <table style="min-width:600px">
            <thead><tr><th>IP العميل</th><th>القناة</th><th>الخادم المستعمل</th><th>الماك</th><th>النجاح</th><th>النشاط</th><th>إجراء</th></tr></thead>
            <tbody id="tb-sessions"></tbody>
          </table>
        </div>
      <div class="card">
        <div class="cardh"><h3><i class="fas fa-info-circle"></i> معلومات</h3></div>
        <div class="fg"><label>رابط Worker</label><div class="urlbox"><span>${W}</span><button class="cpbtn" onclick="cp(this,'${W}')">نسخ</button></div></div>
        <div class="fg"><label>رابط Playlist</label><div class="urlbox"><span>${W}/playlist.m3u?format=m3u8&token=TOKEN</span><button class="cpbtn" onclick="cp(this,'${W}/playlist.m3u?format=m3u8&token=TOKEN')">نسخ</button></div></div>
        <div class="fg"><label>موقعك</label><div class="urlbox" style="direction:ltr;text-align:left"><span id="myip">...</span></div></div>
      </div>
    </div>

    <div class="sec" id="s-tokens">
      <div class="card">
        <div class="cardh"><h3><i class="fas fa-key"></i> التوكنات</h3><button class="btn bg bsm" onclick="openM('m-addtoken')"><i class="fas fa-plus"></i> إضافة</button></div>
        <div style="overflow-x:auto"><table><thead><tr><th>التوكن</th><th>المستخدم</th><th>الانتهاء</th><th>الأيام</th><th>الباقات</th><th>الاستخدام</th><th>الحالة</th><th>IP محظورة</th><th>إجراءات</th></tr></thead><tbody id="tb-tokens"></tbody></table></div>
      </div>
    </div>

    <div class="sec" id="s-macs">
      <div class="card">
        <div class="cardh"><h3><i class="fas fa-network-wired"></i> MACs</h3><button class="btn bg bsm" onclick="openM('m-addmac')"><i class="fas fa-plus"></i> إضافة</button></div>
        <div id="macslist"></div>
      </div>
    </div>

    <div class="sec" id="s-packages">
      <div class="card">
        <div class="cardh"><h3><i class="fas fa-box"></i> الباقات</h3>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button class="btn bg bsm" onclick="openM('m-addpkg')"><i class="fas fa-plus"></i> إضافة</button>
            <button class="btn br bsm" onclick="deleteAllPackages()"><i class="fas fa-trash"></i> حذف الكل</button>
          </div>
        </div>
        <div id="pkgslist" class="pkggrid"></div>
      </div>
    </div>

    <div class="sec" id="s-channels">
      <div class="card">
        <div class="cardh"><h3><i class="fas fa-tv"></i> القنوات</h3>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <select class="fc" id="pkgfilter" style="width:180px" onchange="renderChannels()"><option value="all">جميع الباقات</option></select>
            <input type="text" class="fc" id="chsearch" placeholder="بحث..." style="width:160px" oninput="renderChannels()">
            <button class="btn bg bsm" onclick="openM('m-addch')"><i class="fas fa-plus"></i> إضافة</button>
          </div>
        </div>
        <div id="chslist"></div>
      </div>
    </div>

    <div class="sec" id="s-playlist">
      <div class="card">
        <div class="cardh"><h3><i class="fas fa-file-code"></i> إنشاء M3U</h3></div>
        <div class="fg"><label>نوع الملف</label>
          <div style="display:flex;gap:15px;padding:10px;background:rgba(37,99,235,.1);border-radius:8px;flex-wrap:wrap">
            <label style="cursor:pointer"><input type="radio" name="fmt" value="m3u8" checked> M3U8</label>
            <label style="cursor:pointer"><input type="radio" name="fmt" value="ts"> TS</label>
            <label style="cursor:pointer"><input type="radio" name="fmt" value="mp4"> MP4</label>
            <label style="cursor:pointer"><input type="radio" name="fmt" value="mkv"> MKV</label>
            <label style="cursor:pointer"><input type="radio" name="fmt" value="avi"> AVI</label>
            <label style="cursor:pointer"><input type="radio" name="fmt" value="netlink"> NETLINK</label>
          </div>
        </div>
        <div class="fg"><label>اختر توكن</label><select class="fc" id="pl-token"><option value="">اختر...</option></select></div>
        <div style="display:flex;gap:10px;flex-wrap:wrap">
          <button class="btn bp" onclick="genPlaylist()"><i class="fas fa-link"></i> توليد الرابط</button>
          <button class="btn bg" onclick="dlPlaylist()"><i class="fas fa-download"></i> تحميل</button>
        </div>
        <div id="plresult" style="display:none;margin-top:16px">
          <div class="urlbox"><span id="plurl-text"></span><button class="cpbtn" onclick="cpPlaylist()">نسخ</button></div>
        </div>
      </div>
    </div>

    <div class="sec" id="s-import">
      <div class="card">
        <div class="cardh"><h3><i class="fas fa-upload"></i> رفع ملف M3U</h3></div>
        <div class="uparea" onclick="document.getElementById('m3ufile').click()">
          <i class="fas fa-cloud-upload-alt"></i>
          <h4 style="color:#fff;margin-bottom:6px">اختر ملف أو عدة ملفات M3U</h4>
          <p style="color:#94a3b8;font-size:.9rem">يمكنك تحديد أكثر من ملف لرفعها دفعة واحدة (الرفع الجماعي)</p>
          <input type="file" id="m3ufile" accept=".m3u,.m3u8,.txt" style="display:none" onchange="importM3U(event)" multiple>
        </div>
        <div id="importres" style="margin-top:14px"></div>
      </div>
    </div>

    <div class="sec" id="s-servers">
      <div class="card">
        <div class="cardh"><h3><i class="fas fa-server"></i> الخوادم</h3>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button class="btn bw bsm" onclick="syncHardcoded()"><i class="fas fa-sync"></i> استيراد من الكود</button>
            <button class="btn bw bsm" onclick="cleanupServers()"><i class="fas fa-broom"></i> تنظيف</button>
            <button class="btn bg bsm" onclick="openM('m-addsrv')"><i class="fas fa-plus"></i> إضافة</button>
          </div>
        </div>
        <div id="srvslist"></div>
      </div>
    </div>

    <div class="sec" id="s-adv-settings">
      <div class="card">
        <div class="cardh"><h3><i class="fas fa-tools"></i> إعدادات تحسين البث وفتح القنوات</h3></div>
        <div class="fg">
          <label>عدد الخوادم في السباق الأول (Race Pool Size)</label>
          <input type="number" class="fc" id="adv-race-pool" value="10" min="1" max="20">
          <small style="color:#94a3b8">عدد الخوادم التي يتم تجربتها في وقت واحد لفتح القناة بسرعة.</small>
        </div>
        <div class="fg">
          <label>توقيت المهلة للسباق الأول (Race Timeout ms)</label>
          <input type="number" class="fc" id="adv-race-timeout" value="1500" min="500" max="5000">
          <small style="color:#94a3b8">الوقت (بالملي ثانية) لانتظار أسرع سيرفر في المحاولة الأولى.</small>
        </div>
        <div class="fg">
          <label>توقيت المهلة للسباق الثاني (Fallback Timeout ms)</label>
          <input type="number" class="fc" id="adv-fallback-timeout" value="3000" min="1000" max="10000">
          <small style="color:#94a3b8">الوقت لانتظار السيرفرات المتبقية في حالة فشل المحاولة الأولى.</small>
        </div>
        <div class="fg">
          <label>توقيت Keep-Alive (ثواني)</label>
          <input type="number" class="fc" id="adv-keepalive-timeout" value="5" min="1" max="60">
          <small style="color:#94a3b8">مدة بقاء الاتصال مفتوحاً لتقليل التقطعات.</small>
        </div>
        <div style="margin-top:20px">
          <button class="btn bp" onclick="saveAdvSettings()"><i class="fas fa-save"></i> حفظ الإعدادات</button>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- Modals -->
<div class="modal" id="m-addtoken"><div class="mbox">
  <div class="mh"><h3>إضافة توكن</h3><span class="mcl" onclick="closeM('m-addtoken')">&times;</span></div>
  <div class="fg"><label>اسم المستخدم</label><input type="text" class="fc" id="nt-user" placeholder="user1"></div>
  <div class="fr"><div class="fg"><label>المدة (أيام)</label><input type="number" class="fc" id="nt-days" value="30" min="1"></div><div class="fg"><label>أجهزة</label><input type="number" class="fc" id="nt-dev" value="1" min="1" max="10"></div></div>
  <div class="fg"><label>الباقات</label><div id="nt-pkgs-list" class="pkg-sort-list"></div></div>
  <button class="btn bg" style="width:100%;margin-top:8px" onclick="createToken()"><i class="fas fa-plus"></i> إنشاء</button>
</div></div>

<div class="modal" id="m-edittoken"><div class="mbox">
  <div class="mh"><h3>تعديل التوكن</h3><span class="mcl" onclick="closeM('m-edittoken')">&times;</span></div>
  <input type="hidden" id="et-token">
  <div class="fg"><label>المستخدم</label><input type="text" class="fc" id="et-user"></div>
  <div class="fr"><div class="fg"><label>أجهزة</label><input type="number" class="fc" id="et-dev"></div><div class="fg"><label>الحالة</label><select class="fc" id="et-status"><option value="true">نشط</option><option value="false">معطل</option></select></div></div>
  <div class="fg"><label>الباقات</label><div id="et-pkgs-list" class="pkg-sort-list"></div></div>
  <button class="btn bp" style="width:100%;margin-top:8px" onclick="updateToken()"><i class="fas fa-save"></i> حفظ</button>
</div></div>

<div class="modal" id="m-pkgs"><div class="mbox"><div class="mh"><h3>باقات التوكن</h3><span class="mcl" onclick="closeM('m-pkgs')">&times;</span></div><div id="mc-pkgs"></div></div></div>
<div class="modal" id="m-days"><div class="mbox"><div class="mh"><h3>تعديل الأيام</h3><span class="mcl" onclick="closeM('m-days')">&times;</span></div><div id="mc-days"></div></div></div>
<div class="modal" id="m-blockip"><div class="mbox"><div class="mh"><h3>IPs المحظورة</h3><span class="mcl" onclick="closeM('m-blockip')">&times;</span></div><div id="mc-blockip"></div></div></div>
<div class="modal" id="m-usage"><div class="mbox"><div class="mh"><h3>إحصائيات</h3><span class="mcl" onclick="closeM('m-usage')">&times;</span></div><div id="mc-usage"></div></div></div>

<div class="modal" id="m-addmac"><div class="mbox">
  <div class="mh"><h3>إضافة MAC</h3><span class="mcl" onclick="closeM('m-addmac')">&times;</span></div>
  <div class="fg"><label>MAC Address</label><input type="text" class="fc" id="nm-mac" placeholder="00:1A:79:69:3F:2E" dir="ltr"></div>
  <div class="fr"><div class="fg"><label>الوزن</label><input type="number" class="fc" id="nm-wt" value="5" min="1" max="10"></div><div class="fg"><label>الحالة</label><select class="fc" id="nm-st"><option value="active">نشط</option><option value="inactive">معطل</option></select></div></div>
  <div class="fg"><label>الخادم المخصص</label><select class="fc" id="nm-srv"><option value="">عام</option></select></div>
  <button class="btn bg" style="width:100%;margin-top:8px" onclick="createMAC()"><i class="fas fa-plus"></i> إضافة</button>
</div></div>

<div class="modal" id="m-addpkg"><div class="mbox">
  <div class="mh"><h3>إضافة باقة</h3><span class="mcl" onclick="closeM('m-addpkg')">&times;</span></div>
  <div class="fg"><label>المعرف</label><input type="text" class="fc" id="np-id" placeholder="sports"></div>
  <div class="fg"><label>الاسم</label><input type="text" class="fc" id="np-name" placeholder="رياضة"></div>
  <div class="fg"><label>الأيقونة</label><input type="text" class="fc" id="np-icon" value="📺"></div>
  <div class="fg"><label>رابط الشعار</label><input type="url" class="fc" id="np-logo" placeholder="https://..." dir="ltr"></div>
  <button class="btn bg" style="width:100%;margin-top:8px" onclick="createPkg()"><i class="fas fa-plus"></i> إضافة</button>
</div></div>

<div class="modal" id="m-editpkg"><div class="mbox">
  <div class="mh"><h3>تعديل الباقة</h3><span class="mcl" onclick="closeM('m-editpkg')">&times;</span></div>
  <input type="hidden" id="ep-id">
  <div class="fg"><label>الاسم</label><input type="text" class="fc" id="ep-name"></div>
  <div class="fg"><label>الأيقونة</label><input type="text" class="fc" id="ep-icon"></div>
  <div class="fg"><label>رابط الشعار</label><input type="url" class="fc" id="ep-logo" dir="ltr"></div>
  <button class="btn bp" style="width:100%;margin-top:8px" onclick="updatePkg()"><i class="fas fa-save"></i> حفظ</button>
</div></div>

<div class="modal" id="m-addch"><div class="mbox">
  <div class="mh"><h3>إضافة قناة</h3><span class="mcl" onclick="closeM('m-addch')">&times;</span></div>
  <div class="fg"><label>الباقة</label><select class="fc" id="nc-pkg"></select></div>
  <div class="fg"><label>المعرف</label><input type="text" class="fc" id="nc-id" placeholder="1156649"></div>
  <div class="fg"><label>الاسم</label><input type="text" class="fc" id="nc-name" placeholder="MBC 1"></div>
  <div class="fg"><label>المجموعة</label><input type="text" class="fc" id="nc-grp" placeholder="عربية"></div>
  <button class="btn bg" style="width:100%;margin-top:8px" onclick="createCh()"><i class="fas fa-plus"></i> إضافة</button>
</div></div>

<div class="modal" id="m-editchmac"><div class="mbox">
  <div class="mh"><h3>تعديل القناة</h3><span class="mcl" onclick="closeM('m-editchmac')">&times;</span></div>
  <input type="hidden" id="ech-pkg"><input type="hidden" id="ech-id">
  <div class="fg"><label>الاسم</label><input type="text" class="fc" id="ech-name"></div>
  <div class="fg"><label>المجموعة</label><input type="text" class="fc" id="ech-grp"></div>
  <div class="fg"><label>الشعار</label><input type="text" class="fc" id="ech-logo"></div>
  <div class="fg"><label>الدومينات (سطر لكل دومين)</label><textarea class="fc" id="ech-domains" rows="3" placeholder="domain1.com&#10;domain2.com"></textarea></div>
  <div class="fg"><label>الماكات الخاصة (سطر لكل ماك)</label><textarea class="fc" id="ech-macs" rows="3" placeholder="00:1A:79:00:00:00"></textarea></div>
  <button class="btn bp" style="width:100%;margin-top:8px" onclick="updateCh()"><i class="fas fa-save"></i> حفظ</button>
  <button class="btn bg" style="width:100%;margin-top:6px" onclick="rotateChannelDomains()"><i class="fas fa-sync"></i> تدوير الدومينات</button>
</div></div>

<div class="modal" id="m-addsrv"><div class="mbox">
  <div class="mh"><h3>إضافة خادم</h3><span class="mcl" onclick="closeM('m-addsrv')">&times;</span></div>
  <div class="fg"><label>الاسم</label><input type="text" class="fc" id="ns-name" placeholder="الخادم الرئيسي"></div>
  <div class="fg"><label>الرابط</label><input type="text" class="fc" id="ns-url" placeholder="http://example.com:80"></div>
  <div class="fg"><label>الدومينات (سطر لكل دومين)</label><textarea class="fc" id="ns-domains" rows="3" placeholder="domain1.com&#10;domain2.com&#10;domain3.com"></textarea></div>
  <div class="fg"><label>الماكات الخاصة (سطر لكل ماك)</label><textarea class="fc" id="ns-macs" rows="3" placeholder="00:1A:79:00:00:00&#10;00:1A:79:00:00:01&#10;00:1A:79:00:00:02"></textarea></div>
  <div class="fr"><div class="fg"><label>الوزن</label><input type="number" class="fc" id="ns-wt" value="5"></div><div class="fg"><label>الحالة</label><select class="fc" id="ns-st"><option value="active">نشط</option><option value="inactive">معطل</option></select></div></div>
  <button class="btn bg" style="width:100%;margin-top:8px" onclick="createSrv()"><i class="fas fa-plus"></i> إضافة</button>
</div></div>

<script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
<script src="https://cdn.jsdelivr.net/npm/sortablejs@1.15.0/Sortable.min.js"></script>
<input type="file" id="m3ufile-pkg-input" accept=".m3u,.m3u8,.txt" style="display:none" onchange="importM3UToTargetPkg(event)">
`);

  // JS section as separate string to avoid template literal escape issues
  const js = `
var D={tokens:[],macs:[],packages:{},servers:[],allowedDomains:${allowed}};
var _macPoolData={};
var _targetPkgM3U=null;

function doLogin(){
  var u=(document.getElementById('lu').value||'').trim();
  var p=(document.getElementById('lp').value||'').trim();
  document.getElementById('lerr').style.display='none';
  if(u==='admin'&&p==='admin123'){
    document.getElementById('overlay').style.display='none';
    document.getElementById('app').style.display='block';
    setTimeout(function(){loadData();fetchIP();},50);
  }else{
    document.getElementById('lerr').style.display='block';
  }
}
function doLogout(){
  document.getElementById('overlay').style.display='flex';
  document.getElementById('app').style.display='none';
}
document.addEventListener('keydown',function(e){
  var o=document.getElementById('overlay');
  if(e.key==='Enter'&&o&&o.style.display!=='none')doLogin();
});

function sw(opts){
  if(typeof Swal!=='undefined')Swal.fire(Object.assign({background:'#020617',color:'#fff'},opts));
  else if(opts.icon==='error')alert('Error: '+(opts.text||opts.title||''));
  else if(!opts.timer)alert(opts.title||'Done');
}
async function swalConfirm(msg){
  if(typeof Swal==='undefined')return confirm(msg);
  var r=await Swal.fire({title:msg,icon:'warning',showCancelButton:true,confirmButtonColor:'#dc2626',cancelButtonColor:'#2563eb',confirmButtonText:'نعم',cancelButtonText:'الغاء',background:'#020617',color:'#fff'});
  return r.isConfirmed;
}
function openM(id){updateSelects();var el=document.getElementById(id);if(el)el.classList.add('on');}
function closeM(id){var el=document.getElementById(id);if(el)el.classList.remove('on');}
function cp(btn,text){
  if(!navigator.clipboard){alert(text);return;}
  navigator.clipboard.writeText(text).then(function(){var o=btn.textContent;btn.textContent='v';setTimeout(function(){btn.textContent=o;},1500);}).catch(function(){alert(text.substring(0,100));});
}
function showTab(tab,el){
  document.querySelectorAll('.tab').forEach(function(t){t.classList.remove('on');});
  document.querySelectorAll('.sec').forEach(function(s){s.classList.remove('on');});
  el.classList.add('on');
  var sec=document.getElementById('s-'+tab);if(sec)sec.classList.add('on');
  var titles={dash:'الرئيسية',tokens:'التوكنات',macs:'MACs',packages:'الباقات',channels:'القنوات',playlist:'M3U',import:'رفع M3U',servers:'الخوادم','adv-settings':'الإعدادات المتقدمة'};
  var pt=document.getElementById('ptitle');if(pt)pt.textContent=titles[tab]||tab;
}
function getChannelName(id){
  if(!id)return '';
  var all=Object.values(D.packages||{});
  for(var i=0;i<all.length;i++){var chs=all[i].channels||[];for(var j=0;j<chs.length;j++){if(chs[j].id==id)return chs[j].name;}}
  return id;
}
function pkgImgErr(imgEl,emoji){var p=imgEl.parentNode;if(p)p.innerHTML='<span style="font-size:1.8rem">'+emoji+'</span>';}
function badge(cls,text){return '<span class="badge '+cls+'">'+text+'</span>';}

async function loadData(){
  try{
    var results=await Promise.allSettled([
      fetch('/api/tokens').then(function(r){return r.json();}).catch(function(){return{success:false};}),
      fetch('/api/macs').then(function(r){return r.json();}).catch(function(){return{success:false};}),
      fetch('/api/packages').then(function(r){return r.json();}).catch(function(){return{success:false};}),
      fetch('/api/stats').then(function(r){return r.json();}).catch(function(){return{success:false};}),
      fetch('/api/servers').then(function(r){return r.json();}).catch(function(){return{success:false};}),
      fetch('/api/internal/stats').then(function(r){return r.json();}).catch(function(){return{success:false};}),
      fetch('/api/settings').then(function(r){return r.json();}).catch(function(){return{success:false};})
    ]);
    var td=results[0].value,md=results[1].value,pd=results[2].value,sd=results[3].value,svd=results[4].value,isd=results[5].value,advd=results[6].value;
    D.tokens = (td && td.success) ? (td.data || []) : [];
    D.macs = (md && md.success) ? (md.data || []) : [];
    D.packages = (pd && pd.success) ? (pd.data || {}) : {};
    D.servers = (svd && svd.success) ? (svd.data || []) : [];
    D.internal = (isd && isd.success) ? (isd.data || {scores:{},fails:{},cacheSize:0}) : {scores:{},fails:{},cacheSize:0};
    
    if (advd && advd.success && advd.settings) {
      document.getElementById('adv-race-pool').value = advd.settings.racePoolSize || 10;
      document.getElementById('adv-race-timeout').value = advd.settings.raceTimeout || 1500;
      document.getElementById('adv-fallback-timeout').value = advd.settings.fallbackTimeout || 3000;
      document.getElementById('adv-keepalive-timeout').value = advd.settings.keepAliveTimeout || 5;
    }
    if(sd&&sd.success)updateStats(sd.data);else updateStats(null);
    renderAll();
  }catch(e){sw({icon:'error',title:'خطأ في تحميل البيانات',text:e.message,timer:3000});}
}

// Auto-refresh active sessions every 5 seconds if Dashboard is open
setInterval(async function() {
  if (document.getElementById('s-dash') && document.getElementById('s-dash').classList.contains('on')) {
    try {
      var r = await fetch('/api/internal/stats');
      var d = await r.json();
      if (d && d.success) {
        D.internal = d.data;
        updateStats(null);
      }
    } catch(e) {}
  }
}, 5000);

function updateStats(s){
  var now = Date.now();
  if(!document.getElementById('st-tokens')) return;

  document.getElementById('st-tokens').textContent = s ? (s.tokens || 0) : D.tokens.length;
  document.getElementById('st-active').textContent = s ? (s.activeTokens || 0) : D.tokens.filter(function(t){ return now < t.expiresAt && t.isActive; }).length;
  document.getElementById('st-macs').textContent = s ? (s.macs || 0) : D.macs.length;
  document.getElementById('st-pkgs').textContent = s ? (s.packages || 0) : Object.keys(D.packages).length;
  document.getElementById('st-chs').textContent = s ? (s.totalChannels || 0) : Object.values(D.packages).reduce(function(a,p){ return a + (p.channels || []).length; }, 0);
  document.getElementById('st-srv').textContent = s ? (s.servers || 0) : D.servers.length;
  
  var sessions = D.internal?.sessions || [];
  document.getElementById('st-active-sessions').textContent = sessions.length;
  document.getElementById('st-fails').textContent = Object.keys(D.internal?.fails || {}).length;
  
  var tb = document.getElementById('tb-sessions');
  if(tb){
    if(!sessions.length){ 
        tb.innerHTML = '<tr><td colspan="7" style="text-align:center;color:#94a3b8;padding:15px">لا توجد روابط نشطة حالياً</td></tr>'; 
    } else {
        var html = '';
        for(var i=0; i<sessions.length; i++){
            var sess = sessions[i];
            var ago = Math.floor((Date.now() - sess.ts)/1000);
            var timeStr = ago < 60 ? ago + 'ث' : Math.floor(ago/60) + 'د';
            
            // البحث عن نسبة النجاح للماك (متوافق مع جميع المتصفحات)
            var sr = '--', srC = '#94a3b8';
            for(var j=0; j<D.macs.length; j++){
                if(D.macs[j].mac === sess.mac){
                    var rate = D.macs[j].successRate;
                    sr = (rate !== null && rate !== undefined) ? rate + '%' : '--';
                    srC = rate >= 80 ? '#4ade80' : (rate >= 50 ? '#fbbf24' : '#f87171');
                    break;
                }
            }

            html += '<tr' + (sess.status === 'error' ? ' style="background:rgba(220,38,38,0.15)"' : '') + '>' +
              '<td><code style="color:#60a5fa">' + (sess.ip || 'Unknown') + '</code></td>' +
              '<td>' + getChannelName(sess.ch) + '</td>' +
              '<td><small' + (sess.status === 'error' ? ' style="color:#fca5a5;font-weight:bold"' : '') + '>' + sess.srv + '</small></td>' +
              '<td><code style="color:' + (sess.status === 'error' ? '#fca5a5' : '#fbbf24') + '">' + sess.mac + '</code></td>' +
              '<td><span style="color:' + (sess.status === 'error' ? '#f87171' : srC) + ';font-weight:700">' + (sess.status === 'error' ? 'فشل' : sr) + '</span></td>' +
              '<td>' + badge('badge-info', timeStr) + '</td>' +
              '<td><button class="btn br bsm" onclick="deleteSession(\\\'' + (sess.id || sess.ip) + '\\\')"><i class="fas fa-times"></i></button></td>' +
              '</tr>';
        }
        tb.innerHTML = html;
    }
  }
}
async function deleteSession(id){
  try {
     await fetch('/api/admin/sessions/delete?id='+encodeURIComponent(id), {method:'POST'});
     loadData();
  } catch(e){}
}
async function saveAdvSettings() {
  const settings = {
    racePoolSize: parseInt(document.getElementById('adv-race-pool').value),
    raceTimeout: parseInt(document.getElementById('adv-race-timeout').value),
    fallbackTimeout: parseInt(document.getElementById('adv-fallback-timeout').value),
    keepAliveTimeout: parseInt(document.getElementById('adv-keepalive-timeout').value)
  };
  try {
    const r = await fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ settings })
    });
    const d = await r.json();
    if (d.success) {
      sw({ icon: 'success', title: 'تم حفظ الإعدادات بنجاح', timer: 1500, showConfirmButton: false });
    } else {
      sw({ icon: 'error', title: 'خطأ في الحفظ', text: d.error });
    }
  } catch (e) {
    sw({ icon: 'error', title: 'خطأ في الاتصال', text: e.message });
  }
}

async function clearSessions(){
  if(!await swalConfirm('حذف جميع الروابط النشطة؟')) return;
  try {
     await fetch('/api/admin/sessions/clear', {method:'POST'});
     loadData();
  } catch(e){}
}
async function syncHardcoded(){
  try {
    sw({title:'جاري المزامنة...', showConfirmButton:false});
    var r = await fetch('/api/admin/sync-hardcoded', {method:'POST'});
    var d = await r.json();
    if(d.success) {
      await loadData();
      sw({icon:'success', title:'تمت المزامنة', text: d.message});
    } else {
      sw({icon:'error', title:'خطأ في المزامنة', text: d.error});
    }
  } catch(e) { sw({icon:'error', title:'خطأ', text: e.message}); }
}
async function cleanupServers(){
  var ok = await swalConfirm('سيتم حذف جميع الخوادم غير الموجودة في البيانات الأساسية (DOMAIN_MAC_MAP و AUTO_PORTALS). هل أنت متأكد؟');
  if(!ok) return;
  var keep = D.allowedDomains || [];
  var toDel = D.servers.filter(function(s){ 
     try {
       var h = new URL(s.url).hostname;
       return !keep.includes(h);
     } catch(e) { return true; }
  });
  if(!toDel.length){ sw({icon:'info', title:'تم تنظيف القائمة مسبقاً، كل الخوادم حالية'}); return; }
  for(var s of toDel){
     await fetch('/api/servers/delete', {method:'POST', body: JSON.stringify({id: s.id})});
  }
  await loadData();
  sw({icon:'success', title:'تم حذف ' + toDel.length + ' خادم قديم'});
}
function renderAll(){renderTokens();renderMacs();renderPackages();renderChannels();renderServers();updateSelects();}
function updateSelects(){
  var pkgs=Object.values(D.packages||{});
  var now=Date.now();
  var actTks=D.tokens.filter(function(t){return now<t.expiresAt&&t.isActive;});
  var pf=document.getElementById('pkgfilter');
  if(pf)pf.innerHTML='<option value="all">جميع الباقات</option>'+pkgs.map(function(p){return '<option value="'+p.id+'">'+(p.icon||'')+' '+p.name+'</option>';}).join('');
  var ncpkg=document.getElementById('nc-pkg');
  if(ncpkg)ncpkg.innerHTML='<option value="">اختر...</option>'+pkgs.map(function(p){return '<option value="'+p.id+'">'+(p.icon||'')+' '+p.name+'</option>';}).join('');
  var nmsrv=document.getElementById('nm-srv');
  if(nmsrv)nmsrv.innerHTML='<option value="">عام (لكل الخوادم)</option>'+(D.servers||[]).map(function(s){return '<option value="'+s.id+'">'+s.name+'</option>';}).join('');
  var pli=pkgs.map(function(p){return '<div class="pkg-sort-item" data-id="'+p.id+'"><i class="fas fa-grip-vertical" style="color:#475569"></i><input type="checkbox" value="'+p.id+'"><span style="flex:1;color:#fff">'+(p.icon||'')+' '+p.name+'</span></div>';}).join('');
  var ntp=document.getElementById('nt-pkgs-list');if(ntp){ntp.innerHTML=pli;if(typeof Sortable!=='undefined')new Sortable(ntp,{animation:150});}
  var etp=document.getElementById('et-pkgs-list');if(etp){etp.innerHTML=pli;if(typeof Sortable!=='undefined')new Sortable(etp,{animation:150});}
  var plt=document.getElementById('pl-token');
  if(plt)plt.innerHTML='<option value="">اختر...</option>'+actTks.map(function(t){return '<option value="'+t.token+'">'+t.username+' ('+Math.floor((t.expiresAt-now)/86400000)+' يوم)</option>';}).join('');
}
async function fetchIP(){
  try{
    var r=await fetch('https://ipapi.co/json/');var d=await r.json();
    var el=document.getElementById('myip');
    if(el&&d){var fl=d.country_code?String.fromCodePoint(...[...d.country_code].map(function(c){return 0x1F1E6-65+c.charCodeAt(0);})):'';el.innerHTML=fl+' <strong style="color:#fff">'+(d.country_name||'')+'</strong> &nbsp;<span style="color:#94a3b8">'+(d.ip||'')+'</span>';}
  }catch(e){try{var r2=await fetch('https://api.ipify.org?format=json');var d2=await r2.json();var el2=document.getElementById('myip');if(el2)el2.textContent=d2.ip;}catch(e2){}}
}

// ===== TOKENS =====
function renderTokens(){
  var tb=document.getElementById('tb-tokens');if(!tb)return;
  var now=Date.now();
  if(!D.tokens.length){tb.innerHTML='<tr><td colspan="9" style="text-align:center;color:#94a3b8;padding:20px">لا توجد توكنات</td></tr>';return;}
  tb.innerHTML=D.tokens.map(function(t,i){
    var exp=now>t.expiresAt,days=Math.max(0,Math.floor((t.expiresAt-now)/86400000));
    var sc=exp?'badge-err':(t.isActive?'badge-ok':'badge-warn'),st=exp?'منتهي':(t.isActive?'نشط':'معطل');
    var dc=days>7?'badge-ok':(days>0?'badge-warn':'badge-err');
    return '<tr>'+
      '<td><code style="color:#60a5fa;background:rgba(37,99,235,.1);padding:2px 7px;border-radius:5px">'+t.token+'</code> <button class="btn bi bsm" onclick="showUsage('+i+')"><i class="fas fa-chart-bar"></i></button></td>'+
      '<td>'+t.username+'</td>'+
      '<td style="font-size:.82rem">'+new Date(t.expiresAt).toLocaleDateString('ar-EG')+'</td>'+
      '<td>'+badge(dc,days)+' <button class="btn bp bsm" onclick="showDays('+i+')"><i class="fas fa-calendar-alt"></i></button></td>'+
      '<td><button class="btn bi bsm" onclick="showPkgs('+i+')"><i class="fas fa-box"></i> '+(t.packages||[]).length+'</button></td>'+
      '<td><small style="color:#94a3b8">'+(t.totalUsage||0)+' استخدام</small>'+(t.lastChannel?'<br><small style="color:#60a5fa">&#9654; '+getChannelName(t.lastChannel)+'</small>':'')+'</td>'+
      '<td>'+badge(sc,st)+' <button class="btn '+(t.isActive?'br':'bg')+' bsm" onclick="toggleToken('+i+')"><i class="fas fa-'+(t.isActive?'pause':'play')+'"></i></button></td>'+
      '<td><button class="btn bw bsm" onclick="showBlockIP('+i+')"><i class="fas fa-ban"></i> '+(t.blockedIPsCount||0)+'</button></td>'+
      '<td><button class="btn bp bsm" onclick="editToken('+i+')"><i class="fas fa-edit"></i></button> <button class="btn br bsm" onclick="delToken('+i+')"><i class="fas fa-trash"></i></button></td>'+
      '</tr>';
  }).join('');
}
async function createToken(){
  var user=document.getElementById('nt-user').value.trim(),days=parseInt(document.getElementById('nt-days').value),dev=parseInt(document.getElementById('nt-dev').value)||1;
  var items=Array.from(document.querySelectorAll('#nt-pkgs-list .pkg-sort-item'));
  var pkgs=items.filter(function(el){return el.querySelector('input').checked;}).map(function(el){return el.getAttribute('data-id');});
  if(!user){sw({icon:'error',title:'ادخل اسم المستخدم'});return;}
  if(!days||days<1){sw({icon:'error',title:'ادخل مدة صحيحة'});return;}
  try{
    var r=await fetch('/api/tokens/create',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:user,duration:days,maxDevices:dev,packages:pkgs})});
    var d=await r.json();
    if(d.success){closeM('m-addtoken');document.getElementById('nt-user').value='';await loadData();sw({icon:'success',title:'تم انشاء التوكن',html:'<div style="background:rgba(37,99,235,.1);border-radius:10px;padding:16px;margin:10px 0"><div style="font-family:monospace;font-size:2rem;color:#60a5fa;letter-spacing:4px">'+d.data.token+'</div></div>'});}
    else sw({icon:'error',title:'خطا',text:d.error});
  }catch(e){sw({icon:'error',title:'خطا',text:e.message});}
}
async function toggleToken(idx){
  var t=D.tokens[idx];if(!t)return;
  try{
    var r=await fetch('/api/tokens/update',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:t.token,updates:{isActive:!t.isActive}})});
    var d=await r.json();
    if(d.success){t.isActive=!t.isActive;renderTokens();sw({icon:'success',title:t.isActive?'تم التشغيل':'تم الايقاف',timer:800,showConfirmButton:false});}
    else sw({icon:'error',title:'خطا',text:d.error});
  }catch(e){sw({icon:'error',title:'خطا',text:e.message});}
}
function editToken(idx){
  var t=D.tokens[idx];if(!t)return;
  document.getElementById('et-token').value=t.token;
  document.getElementById('et-user').value=t.username||'';
  document.getElementById('et-dev').value=t.maxDevices||1;
  document.getElementById('et-status').value=t.isActive?'true':'false';
  var list=document.getElementById('et-pkgs-list');
  if(list){
    var sel=t.packages||[],all=Object.values(D.packages);
    var items=all.map(function(p){return{id:p.id,icon:p.icon,name:p.name,checked:sel.includes(p.id)};});
    items.sort(function(a,b){var ia=sel.indexOf(a.id),ib=sel.indexOf(b.id);if(ia>-1&&ib>-1)return ia-ib;if(ia>-1)return -1;if(ib>-1)return 1;return 0;});
    list.innerHTML=items.map(function(p){return '<div class="pkg-sort-item" data-id="'+p.id+'"><i class="fas fa-grip-vertical" style="color:#475569"></i><input type="checkbox" value="'+p.id+'" '+(p.checked?'checked':'')+'>  <span style="flex:1;color:#fff">'+(p.icon||'')+' '+p.name+'</span></div>';}).join('');
    if(typeof Sortable!=='undefined')new Sortable(list,{animation:150});
  }
  openM('m-edittoken');
}
async function updateToken(){
  var token=document.getElementById('et-token').value,user=document.getElementById('et-user').value.trim();
  var dev=parseInt(document.getElementById('et-dev').value)||1,active=document.getElementById('et-status').value==='true';
  var items=Array.from(document.querySelectorAll('#et-pkgs-list .pkg-sort-item'));
  var pkgs=items.filter(function(el){return el.querySelector('input').checked;}).map(function(el){return el.getAttribute('data-id');});
  if(!user){sw({icon:'error',title:'ادخل المستخدم'});return;}
  try{
    var r=await fetch('/api/tokens/update',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:token,updates:{username:user,maxDevices:dev,isActive:active,packages:pkgs}})});
    var d=await r.json();
    if(d.success){closeM('m-edittoken');await loadData();sw({icon:'success',title:'تم التحديث',timer:1000,showConfirmButton:false});}
    else sw({icon:'error',title:'خطا',text:d.error});
  }catch(e){sw({icon:'error',title:'خطا',text:e.message});}
}
async function delToken(idx){
  var t=D.tokens[idx];if(!t)return;
  var ok=await swalConfirm('حذف التوكن '+t.token+'?');if(!ok)return;
  try{
    var r=await fetch('/api/tokens/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:t.token})});
    var d=await r.json();
    if(d.success){await loadData();sw({icon:'success',title:'تم الحذف',timer:1000,showConfirmButton:false});}
  }catch(e){sw({icon:'error',title:'خطا',text:e.message});}
}
async function showUsage(idx){
  var t=D.tokens[idx];if(!t)return;
  try{
    var r=await fetch('/api/tokens/usage?token='+encodeURIComponent(t.token));var d=await r.json();
    if(!d.success){sw({icon:'error',title:'خطا',text:d.error});return;}
    var td=d.data,now2=Date.now();
    var pkgsHtml=(td.packagesWithDetails||[]).map(function(p){return '<span class="ptag">'+(p.icon||'')+' '+p.name+'</span>';}).join('')||'<span style="color:#94a3b8">لا توجد</span>';
    var sc2=now2>td.expiresAt?'badge-err':(td.isActive?'badge-ok':'badge-warn');
    document.getElementById('mc-usage').innerHTML='<div class="tbox"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px"><h4 style="color:#60a5fa">'+td.username+'</h4>'+badge(sc2,now2>td.expiresAt?'منتهي':(td.isActive?'نشط':'معطل'))+'</div><div style="margin-bottom:10px"><strong style="color:#94a3b8">الباقات:</strong><br>'+pkgsHtml+'</div><div class="tstats"><div class="tstat"><div class="tstatv">'+(td.totalUsage||0)+'</div><div class="tstatl">استخدامات</div></div><div class="tstat"><div class="tstatv">'+Math.max(0,Math.floor((td.expiresAt-now2)/86400000))+'</div><div class="tstatl">يوم متبقي</div></div></div>'+(td.lastIp?'<div style="margin-top:5px;padding:8px;background:rgba(0,0,0,.2);border-radius:7px"><i class="fas fa-network-wired" style="color:#fbbf24"></i> آخر IP: <code style="direction:ltr">'+td.lastIp+'</code></div>':'')+'</div>';
    openM('m-usage');
  }catch(e){sw({icon:'error',title:'خطا',text:e.message});}
}
async function showPkgs(idx){
  var t=D.tokens[idx];if(!t)return;
  var cur=t.packages||[],allPkgs=Object.values(D.packages);
  var curHtml=cur.length?cur.map(function(pid,pi){var p=D.packages[pid];return '<div class="sortitem" data-id="'+pid+'"><i class="fas fa-grip-vertical grip"></i><span>'+(p?(p.icon||'')+' '+p.name:pid)+'</span><button class="btn br bsm" onclick="removePkg('+idx+','+pi+')" style="margin-right:auto"><i class="fas fa-times"></i></button></div>';}).join(''):'<p style="color:#94a3b8;text-align:center">لا توجد باقات</p>';
  var addOpts=allPkgs.filter(function(p){return !cur.includes(p.id);}).map(function(p){return '<option value="'+p.id+'">'+(p.icon||'')+' '+p.name+'</option>';}).join('');
  document.getElementById('mc-pkgs').innerHTML='<div class="tbox"><h4 style="color:#60a5fa;margin-bottom:10px">'+t.username+'</h4><div style="margin-bottom:12px"><strong style="color:#94a3b8;display:block;margin-bottom:6px">الباقات:</strong><div id="pkgs-sort">'+curHtml+'</div></div><div><strong style="color:#94a3b8;display:block;margin-bottom:6px">اضافة باقة:</strong><div style="display:flex;gap:8px"><select class="fc" id="addpkgsel"><option value="">اختر...</option>'+addOpts+'</select><button class="btn bg" onclick="addPkgToToken('+idx+')"><i class="fas fa-plus"></i></button></div></div></div>';
  openM('m-pkgs');
  if(cur.length&&typeof Sortable!=='undefined'){new Sortable(document.getElementById('pkgs-sort'),{animation:150,handle:'.grip',onEnd:function(){var order=Array.from(document.getElementById('pkgs-sort').children).map(function(c){return c.dataset.id;}).filter(Boolean);fetch('/api/tokens/packages/reorder',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:t.token,packages:order})});}});}
}
async function addPkgToToken(idx){
  var t=D.tokens[idx];if(!t)return;
  var pid=document.getElementById('addpkgsel').value;
  if(!pid){sw({icon:'warning',title:'اختر باقة'});return;}
  try{
    var r=await fetch('/api/tokens/packages/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:t.token,packageId:pid})});
    var d=await r.json();
    if(d.success){closeM('m-pkgs');await loadData();sw({icon:'success',title:'تمت الاضافة',timer:1000,showConfirmButton:false});}
    else sw({icon:'error',title:'خطا',text:d.error});
  }catch(e){sw({icon:'error',title:'خطا',text:e.message});}
}
async function removePkg(ti,pi){
  var t=D.tokens[ti];if(!t)return;
  var pid=(t.packages||[])[pi];if(!pid)return;
  try{
    var r=await fetch('/api/tokens/packages/remove',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:t.token,packageId:pid})});
    var d=await r.json();if(d.success){closeM('m-pkgs');await loadData();}
  }catch(e){}
}
function showDays(idx){
  var t=D.tokens[idx];if(!t)return;
  var now=Date.now(),days=Math.max(0,Math.floor((t.expiresAt-now)/86400000));
  var dc=days>7?'#4ade80':(days>0?'#fbbf24':'#f87171');
  document.getElementById('mc-days').innerHTML='<div class="tbox"><h4 style="color:#60a5fa;margin-bottom:10px">'+t.username+'</h4><div style="text-align:center;margin-bottom:16px;padding:12px;background:rgba(0,0,0,.2);border-radius:9px"><div style="font-size:2.5rem;font-weight:700;color:'+dc+'">'+days+'</div><div style="color:#94a3b8">يوم متبقي</div></div><div style="display:grid;grid-template-columns:1fr 1fr;gap:12px"><div><label style="color:#4ade80;display:block;margin-bottom:5px;font-weight:600">اضافة ايام</label><input type="number" class="fc" id="add-days" value="30" min="1"><button class="btn bg" style="width:100%;margin-top:6px" onclick="addDays('+idx+')">اضافة</button></div><div><label style="color:#f87171;display:block;margin-bottom:5px;font-weight:600">نقص ايام</label><input type="number" class="fc" id="rem-days" value="1" min="1"><button class="btn br" style="width:100%;margin-top:6px" onclick="remDays('+idx+')">نقص</button></div></div></div>';
  openM('m-days');
}
async function addDays(idx){
  var t=D.tokens[idx];if(!t)return;
  var days=parseInt(document.getElementById('add-days').value)||0;if(days<1)return;
  try{var r=await fetch('/api/tokens/days/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:t.token,days:days})});var d=await r.json();if(d.success){closeM('m-days');await loadData();sw({icon:'success',title:'تمت اضافة '+days+' يوم',timer:1200,showConfirmButton:false});}else sw({icon:'error',title:'خطا',text:d.error});}catch(e){sw({icon:'error',title:'خطا',text:e.message});}
}
async function remDays(idx){
  var t=D.tokens[idx];if(!t)return;
  var days=parseInt(document.getElementById('rem-days').value)||0;if(days<1)return;
  try{var r=await fetch('/api/tokens/days/remove',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:t.token,days:days})});var d=await r.json();if(d.success){closeM('m-days');await loadData();sw({icon:'success',title:'تم نقص '+days+' يوم',timer:1200,showConfirmButton:false});}else sw({icon:'error',title:'خطا',text:d.error});}catch(e){sw({icon:'error',title:'خطا',text:e.message});}
}
async function showBlockIP(idx){
  var t=D.tokens[idx];if(!t)return;
  try{
    var r=await fetch('/api/tokens/blocked-ips?token='+encodeURIComponent(t.token));var d=await r.json();
    var ips=d.success?(d.blockedIPs||[]):[];
    var ipsHtml=ips.length?ips.map(function(ip,ii){return '<div class="iperr"><span style="font-family:monospace;color:#f87171;direction:ltr">'+ip+'</span><button class="btn bg bsm" onclick="unblockIP('+idx+','+ii+')"><i class="fas fa-unlock"></i></button></div>';}).join(''):'<p style="color:#94a3b8;text-align:center;padding:8px">لا توجد IPs محظورة</p>';
    document.getElementById('mc-blockip').innerHTML='<div class="tbox"><h4 style="color:#60a5fa;margin-bottom:10px">'+t.username+'</h4><div style="display:flex;gap:8px;margin-bottom:12px"><input type="text" class="fc" id="newip" placeholder="1.2.3.4" dir="ltr" style="flex:1"><button class="btn br" onclick="blockIP('+idx+')"><i class="fas fa-ban"></i> حظر</button></div><strong style="color:#f87171;display:block;margin-bottom:6px">محظورة ('+ips.length+'):</strong><div>'+ipsHtml+'</div></div>';
    openM('m-blockip');
  }catch(e){sw({icon:'error',title:'خطا',text:e.message});}
}
async function blockIP(idx){var t=D.tokens[idx];if(!t)return;var ip=(document.getElementById('newip').value||'').trim();if(!ip)return;try{var r=await fetch('/api/tokens/block-ip',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:t.token,ip:ip,action:'block'})});var d=await r.json();if(d.success){showBlockIP(idx);loadData();}else sw({icon:'error',title:'خطا',text:d.error});}catch(e){sw({icon:'error',title:'خطا',text:e.message});}}
async function unblockIP(ti,ii){var t=D.tokens[ti];if(!t)return;try{var r=await fetch('/api/tokens/blocked-ips?token='+encodeURIComponent(t.token));var d=await r.json();var ips=d.success?(d.blockedIPs||[]):[];var ip=ips[ii];if(!ip)return;var r2=await fetch('/api/tokens/block-ip',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:t.token,ip:ip,action:'unblock'})});var d2=await r2.json();if(d2.success){showBlockIP(ti);loadData();}}catch(e){}}

// ===== MACs =====
async function loadMacPoolUI(){try{var r=await fetch('/api/macs/pool');var d=await r.json();if(d.success&&d.data){_macPoolData={primary:d.data.primary,map:{}};(d.data.macs||[]).forEach(function(m){_macPoolData.map[m.mac]=m;});}}catch(e){}}
function renderMacs(){
  var el=document.getElementById('macslist');if(!el)return;
  if(!D.macs.length){el.innerHTML='<p style="color:#94a3b8;text-align:center;padding:18px">لا توجد MACs</p>';return;}
  loadMacPoolUI().then(function(){
    var primary=(_macPoolData&&_macPoolData.primary)||'';
    el.innerHTML=D.macs.map(function(m,i){
      var sr=m.successRate!==null&&m.successRate!==undefined?m.successRate:(m.totalRequests>0?Math.round(m.successCount/m.totalRequests*100):null);
      var srC=sr===null?'#94a3b8':(sr>=80?'#4ade80':(sr>=50?'#fbbf24':'#f87171'));
      var pool=(_macPoolData.map&&_macPoolData.map[m.mac])||{};
      var isPrimary=m.mac===primary;
      var srvName='';if(m.serverId){var sv=D.servers.find(function(s){return s.id===m.serverId;});srvName=sv?sv.name:'';}
      var badges='';
      if(isPrimary)badges+=badge('badge-ok','&#9733; اساسي');
      if(pool.disabledSec>0)badges+='<span class="badge" style="background:#7c3aed">&#9646;&#9646; راحة '+pool.disabledSec+'ث</span>';
      if(srvName)badges+=badge('badge-info','&#128424; '+srvName);
      return '<div class="macitem" style="'+(isPrimary?'border-color:#4ade80;background:rgba(74,222,128,.05)':'')+'"><div style="flex:1;min-width:0"><div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap"><div style="font-family:monospace;direction:ltr;color:#60a5fa">'+m.mac+'</div>'+badges+'</div><div style="display:flex;align-items:center;gap:10px;margin-top:4px"><span style="color:'+srC+';font-weight:700;font-size:.9rem">'+(sr!==null?sr+'%':'--')+'</span><span style="color:#94a3b8;font-size:.78rem">/ '+(m.totalRequests||0)+' طلب</span>'+(m.avgResponseTime?'<span style="color:#60a5fa;font-size:.78rem">'+Math.round(m.avgResponseTime)+'ms</span>':'')+'</div></div><div style="display:flex;align-items:center;gap:5px;flex-shrink:0">'+badge(m.active?'badge-ok':'badge-warn',m.active?'نشط':'معطل')+'<button class="btn bp bsm" onclick="editMAC('+i+')"><i class="fas fa-edit"></i></button><button class="btn bi bsm" onclick="resetMAC('+i+')"><i class="fas fa-redo"></i></button><button class="btn br bsm" onclick="delMAC('+i+')"><i class="fas fa-trash"></i></button></div></div>';
    }).join('');
  });
}
async function createMAC(){
  var mac=(document.getElementById('nm-mac').value||'').trim().toUpperCase();
  var wt=parseInt(document.getElementById('nm-wt').value)||5,active=document.getElementById('nm-st').value==='active';
  var srvId=(document.getElementById('nm-srv')||{}).value||'';
  if(!/^([0-9A-F]{2}:){5}[0-9A-F]{2}$/.test(mac)){sw({icon:'error',title:'صيغة MAC غير صحيحة'});return;}
  var nm={id:Date.now().toString(),mac:mac,weight:wt,active:active,serverId:srvId,successCount:0,failCount:0,totalRequests:0,avgResponseTime:0,lastUsed:null};
  D.macs.push(nm);
  try{var r=await fetch('/api/macs',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({macs:D.macs})});var d=await r.json();if(d.success){closeM('m-addmac');document.getElementById('nm-mac').value='';renderMacs();sw({icon:'success',title:'تمت الاضافة',timer:1200,showConfirmButton:false});}else{D.macs=D.macs.filter(function(m){return m.id!==nm.id;});renderMacs();sw({icon:'error',title:'خطا',text:d.error});}}catch(e){D.macs=D.macs.filter(function(m){return m.id!==nm.id;});renderMacs();sw({icon:'error',title:'خطا',text:e.message});}
}
async function editMAC(idx){
  var m=D.macs[idx];if(!m)return;
  if(typeof Swal==='undefined'){alert('حمل الصفحة مجددا');return;}
  var srvOpts='<option value="">عام</option>'+D.servers.map(function(s){return '<option value="'+s.id+'"'+(m.serverId===s.id?' selected':'')+'>'+s.name+'</option>';}).join('');
  Swal.fire({title:'تعديل MAC',background:'#020617',color:'#fff',html:'<div style="text-align:right"><label style="color:#94a3b8;display:block;margin-bottom:3px">MAC</label><input id="em" class="swal2-input" value="'+m.mac+'" dir="ltr" style="color:#fff;background:#0f172a"><label style="color:#94a3b8;display:block;margin-top:8px;margin-bottom:3px">الوزن</label><input id="ew" type="number" class="swal2-input" value="'+m.weight+'" min="1" max="10" style="color:#fff;background:#0f172a"><label style="color:#94a3b8;display:block;margin-top:8px;margin-bottom:3px">الحالة</label><select id="ea" style="width:100%;padding:10px;background:#0f172a;color:#fff;border:1px solid #334155;border-radius:7px;margin-bottom:8px"><option value="true"'+(m.active?' selected':'')+'>نشط</option><option value="false"'+(!m.active?' selected':'')+'>معطل</option></select><label style="color:#94a3b8;display:block;margin-bottom:3px">الخادم</label><select id="es" style="width:100%;padding:10px;background:#0f172a;color:#fff;border:1px solid #334155;border-radius:7px">'+srvOpts+'</select></div>',showCancelButton:true,confirmButtonText:'حفظ',cancelButtonText:'الغاء',preConfirm:async function(){var nm2=document.getElementById('em').value.trim().toUpperCase();if(!/^([0-9A-F]{2}:){5}[0-9A-F]{2}$/.test(nm2)){Swal.showValidationMessage('صيغة MAC غير صحيحة');return false;}var r=await fetch('/api/macs/update',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({macId:m.id,updates:{mac:nm2,weight:parseInt(document.getElementById('ew').value)||5,active:document.getElementById('ea').value==='true',serverId:document.getElementById('es').value||''}})});var d=await r.json();if(!d.success){Swal.showValidationMessage(d.error||'خطا');return false;}return true;}}).then(function(res){if(res.isConfirmed)loadData();});
}
async function resetMAC(idx){var m=D.macs[idx];if(!m)return;var ok=await swalConfirm('اعادة تعيين احصائيات MAC؟');if(!ok)return;try{var r=await fetch('/api/macs/reset-stats',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({macId:m.id})});var d=await r.json();if(d.success){loadData();sw({icon:'success',title:'تم',timer:800,showConfirmButton:false});}}catch(e){}}
async function delMAC(idx){var m=D.macs[idx];if(!m)return;var ok=await swalConfirm('حذف MAC؟');if(!ok)return;D.macs=D.macs.filter(function(x){return x.id!==m.id;});renderMacs();try{await fetch('/api/macs',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({macs:D.macs})});}catch(e){}}

// ===== PACKAGES =====
function renderPackages(){
  var el=document.getElementById('pkgslist');if(!el)return;
  var pkgs=Object.values(D.packages||{});
  if(!pkgs.length){el.innerHTML='<p style="color:#94a3b8;text-align:center;padding:18px">لا توجد باقات. ارفع M3U او اضف يدويا.</p>';return;}
  el.innerHTML=pkgs.map(function(p,i){
    var iconHtml=p.logo?'<div style="width:60px;height:60px;flex-shrink:0;border-radius:12px;overflow:hidden;background:rgba(37,99,235,.1);display:flex;align-items:center;justify-content:center;border:2px solid rgba(37,99,235,.2)"><img src="'+p.logo+'" style="width:100%;height:100%;object-fit:contain" data-emoji="'+encodeURIComponent(p.icon||'TV')+'" onerror="pkgImgErr(this,decodeURIComponent(this.dataset.emoji))"></div>':'<div style="width:60px;height:60px;flex-shrink:0;border-radius:12px;background:rgba(37,99,235,.1);display:flex;align-items:center;justify-content:center;font-size:2rem;border:2px solid rgba(37,99,235,.2)">'+(p.icon||'TV')+'</div>';
    return '<div class="pkgcard" data-id="'+p.id+'"><div style="display:flex;align-items:center;gap:15px;margin-bottom:12px">'+iconHtml+'<div style="flex:1;min-width:0"><div style="color:#fff;font-weight:700;font-size:1.1rem">'+p.name+'</div><div style="color:#94a3b8;font-size:.85rem">'+(p.channels||[]).length+' قناة</div></div><div style="color:#475569;font-size:1.2rem"><i class="fas fa-grip-vertical"></i></div></div><div style="display:flex;gap:7px"><button class="btn bp bsm" style="flex:1" onclick="editPkg('+i+')"><i class="fas fa-edit"></i> تعديل</button><button class="btn bs bsm" data-pkgid="'+encodeURIComponent(p.id)+'" onclick="importPkgM3U(decodeURIComponent(this.dataset.pkgid))"><i class="fas fa-file-audio"></i></button><button class="btn bi bsm" data-pkgid="'+encodeURIComponent(p.id)+'" onclick="reorderChannels(decodeURIComponent(this.dataset.pkgid))"><i class="fas fa-sort"></i></button><button class="btn br bsm" onclick="delPkg('+i+')"><i class="fas fa-trash"></i></button></div></div>';
  }).join('');
  if(typeof Sortable!=='undefined'){new Sortable(el,{animation:150,handle:'.pkgcard',ghostClass:'pkgcard-ghost',onEnd:async function(){var order=Array.from(el.children).map(function(c){return c.getAttribute('data-id');});try{await fetch('/api/packages/reorder',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({order:order})});var np={};order.forEach(function(pid){np[pid]=D.packages[pid];});D.packages=np;renderAll();sw({icon:'success',title:'تم حفظ الترتيب',timer:800,showConfirmButton:false});}catch(e){}}}); }
}
async function createPkg(){
  var id=(document.getElementById('np-id').value||'').trim().replace(/\s+/g,'_').toLowerCase();
  var name=(document.getElementById('np-name').value||'').trim(),icon=(document.getElementById('np-icon').value||'').trim(),logo=(document.getElementById('np-logo').value||'').trim();
  if(!id||!name){sw({icon:'error',title:'ادخل المعرف والاسم'});return;}
  if(D.packages[id]){sw({icon:'error',title:'المعرف موجود مسبقا'});return;}
  D.packages[id]={id:id,name:name,icon:icon,logo:logo,channels:[]};renderPackages();updateSelects();
  try{var r=await fetch('/api/packages',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({packages:D.packages})});var d=await r.json();if(d.success){closeM('m-addpkg');sw({icon:'success',title:'تمت الاضافة',timer:1000,showConfirmButton:false});}else{delete D.packages[id];renderPackages();updateSelects();sw({icon:'error',title:'خطا',text:d.error});}}catch(e){delete D.packages[id];renderPackages();updateSelects();sw({icon:'error',title:'خطا',text:e.message});}
}
function editPkg(idx){
  var p=Object.values(D.packages)[idx];if(!p)return;
  document.getElementById('ep-id').value=p.id;document.getElementById('ep-name').value=p.name||'';document.getElementById('ep-icon').value=p.icon||'';document.getElementById('ep-logo').value=p.logo||'';
  openM('m-editpkg');
}
async function updatePkg(){
  var id=document.getElementById('ep-id').value,name=document.getElementById('ep-name').value.trim();
  var icon=document.getElementById('ep-icon').value.trim(),logo=document.getElementById('ep-logo').value.trim();
  if(!name){sw({icon:'error',title:'ادخل الاسم'});return;}
  try{var r=await fetch('/api/packages/update',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({packageId:id,updates:{name:name,icon:icon,logo:logo}})});var d=await r.json();if(d.success){closeM('m-editpkg');await loadData();sw({icon:'success',title:'تم التحديث',timer:1000,showConfirmButton:false});}else sw({icon:'error',title:'خطا',text:d.error});}catch(e){sw({icon:'error',title:'خطا',text:e.message});}
}
async function delPkg(idx){
  var p=Object.values(D.packages)[idx];if(!p)return;
  var ok=await swalConfirm('حذف الباقة '+p.name+'؟');if(!ok)return;
  try{var r=await fetch('/api/packages/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({packageId:p.id})});var d=await r.json();if(d.success){await loadData();sw({icon:'success',title:'تم الحذف',timer:800,showConfirmButton:false});}}catch(e){}
}
async function deleteAllPackages(){
  var ok=await swalConfirm('هل أنت متأكد من حذف جميع الباقات؟ هذا الإجراء لا يمكن التراجع عنه!');if(!ok)return;
  try{var r=await fetch('/api/packages/delete-all',{method:'POST',headers:{'Content-Type':'application/json'}});var d=await r.json();if(d.success){await loadData();sw({icon:'success',title:'تم حذف جميع الباقات',timer:1500,showConfirmButton:false});}else sw({icon:'error',title:'خطا',text:d.error});}catch(e){sw({icon:'error',title:'خطا',text:e.message});}
}

// ===== CHANNELS =====
function renderChannels(){
  var el=document.getElementById('chslist');if(!el)return;
  var filter=(document.getElementById('pkgfilter')||{}).value||'all';
  var search=((document.getElementById('chsearch')||{}).value||'').toLowerCase();
  var channels=[];
  if(filter!=='all'){var p2=D.packages[filter];if(p2)(p2.channels||[]).forEach(function(c){channels.push(Object.assign({},c,{packageId:filter,packageName:p2.name,packageIcon:p2.icon}));});}
  else{Object.entries(D.packages||{}).forEach(function(e){(e[1].channels||[]).forEach(function(c){channels.push(Object.assign({},c,{packageId:e[0],packageName:e[1].name,packageIcon:e[1].icon}));});});}
  if(search)channels=channels.filter(function(c){return(c.name||'').toLowerCase().includes(search)||(c.id||'').toLowerCase().includes(search);});
  if(!channels.length){el.innerHTML='<p style="color:#94a3b8;text-align:center;padding:18px">لا توجد قنوات</p>';return;}
  var sortable=(filter!=='all'&&!search);
  el.innerHTML=sortable
    ?'<div style="background:rgba(37,99,235,.08);border:1px solid var(--p);border-radius:8px;padding:8px;margin-bottom:10px;color:#60a5fa;font-size:.85rem">اسحب القنوات لتغيير الترتيب ثم اضغط حفظ</div><div id="ch-sortable-list">'+
      channels.map(function(c,i){return '<div class="sortitem" data-pkgid="'+c.packageId+'" data-chid="'+c.id+'" style="cursor:grab"><i class="fas fa-grip-vertical grip" style="color:#475569;margin-left:6px"></i>'+(c.logo?'<img src="'+c.logo+'" style="width:28px;height:28px;border-radius:4px;object-fit:contain;flex-shrink:0">':'')+'<span style="color:#fff;flex:1">'+c.name+'</span><span style="color:#94a3b8;font-size:.78rem;direction:ltr">['+c.id+']</span><button class="btn bp bsm" onclick="editCh('+i+')"><i class="fas fa-edit"></i></button><button class="btn br bsm" data-chkey="'+encodeURIComponent(c.packageId+':'+c.id)+'" onclick="delChById(decodeURIComponent(this.dataset.chkey))"><i class="fas fa-trash"></i></button></div>';}).join('')+
      '</div><div style="margin-top:10px"><button class="btn bg" onclick="saveChOrder()"><i class="fas fa-save"></i> حفظ الترتيب</button></div>'
    :channels.map(function(c,i){return '<div class="sortitem">'+(c.logo?'<img src="'+c.logo+'" style="width:28px;height:28px;border-radius:4px;object-fit:contain;flex-shrink:0">':'')+'<span style="color:#fff;flex:1">'+c.name+'</span><span style="color:#94a3b8;font-size:.82rem;margin:0 8px">['+c.id+']</span>'+badge('badge-info',(c.packageIcon||'')+' '+c.packageName)+'<button class="btn bp bsm" onclick="editCh('+i+')"><i class="fas fa-edit"></i></button><button class="btn br bsm" data-chkey="'+encodeURIComponent(c.packageId+':'+c.id)+'" onclick="delChById(decodeURIComponent(this.dataset.chkey))"><i class="fas fa-trash"></i></button></div>';}).join('');
  if(sortable&&typeof Sortable!=='undefined'){var listEl=document.getElementById('ch-sortable-list');if(listEl)new Sortable(listEl,{animation:150,handle:'.grip'});}
}
async function saveChOrder(){
  var filter=(document.getElementById('pkgfilter')||{}).value||'all';
  if(filter==='all'||!D.packages[filter])return;
  var listEl=document.getElementById('ch-sortable-list');if(!listEl)return;
  var newOrder=Array.from(listEl.children).map(function(el){return el.getAttribute('data-chid');}).filter(Boolean);
  var oldChs=D.packages[filter].channels||[],chMap={};
  oldChs.forEach(function(c){chMap[c.id]=c;});
  var reordered=newOrder.map(function(id){return chMap[id];}).filter(Boolean);
  oldChs.forEach(function(c){if(!newOrder.includes(c.id))reordered.push(c);});
  try{var r=await fetch('/api/channels/reorder',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({packageId:filter,channels:reordered})});var d=await r.json();if(d.success){D.packages[filter].channels=reordered;sw({icon:'success',title:'تم حفظ الترتيب',timer:1000,showConfirmButton:false});}else sw({icon:'error',title:'خطا',text:d.error});}catch(e){sw({icon:'error',title:'خطا',text:e.message});}
}
function reorderChannels(pkgId){
  var pf=document.getElementById('pkgfilter');if(pf)pf.value=pkgId;
  document.querySelectorAll('.tab').forEach(function(t){t.classList.remove('on');});
  document.querySelectorAll('.sec').forEach(function(s){s.classList.remove('on');});
  var chTab=document.querySelector('.tab[onclick*="channels"]');if(chTab)chTab.classList.add('on');
  var chSec=document.getElementById('s-channels');if(chSec)chSec.classList.add('on');
  renderChannels();
}
async function createCh(){
  var pkg=document.getElementById('nc-pkg').value,id=(document.getElementById('nc-id').value||'').trim();
  var name=(document.getElementById('nc-name').value||'').trim(),grp=(document.getElementById('nc-grp').value||'').trim()||'IPTV';
  if(!pkg||!id||!name){sw({icon:'error',title:'ادخل جميع البيانات'});return;}
  if(!D.packages[pkg]){sw({icon:'error',title:'الباقة غير موجودة'});return;}
  if(!D.packages[pkg].channels)D.packages[pkg].channels=[];
  var ch={id:id,name:name,group:grp,number:D.packages[pkg].channels.length+1};
  D.packages[pkg].channels.push(ch);renderChannels();
  try{var r=await fetch('/api/packages',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({packages:D.packages})});var d=await r.json();if(d.success){closeM('m-addch');sw({icon:'success',title:'تمت الاضافة',timer:1000,showConfirmButton:false});}else{D.packages[pkg].channels=D.packages[pkg].channels.filter(function(c){return c.id!==id;});renderChannels();sw({icon:'error',title:'خطا',text:d.error});}}catch(e){D.packages[pkg].channels=D.packages[pkg].channels.filter(function(c){return c.id!==id;});renderChannels();}
}
function editCh(idx){
  var filter=(document.getElementById('pkgfilter')||{}).value||'all';
  var channels=[];
  if(filter!=='all'){var p4=D.packages[filter];if(p4)(p4.channels||[]).forEach(function(c){channels.push(Object.assign({},c,{packageId:filter}));});}
  else{Object.entries(D.packages||{}).forEach(function(e){(e[1].channels||[]).forEach(function(c){channels.push(Object.assign({},c,{packageId:e[0]}));});});}
  var search=((document.getElementById('chsearch')||{}).value||'').toLowerCase();
  if(search)channels=channels.filter(function(c){return(c.name||'').toLowerCase().includes(search)||(c.id||'').toLowerCase().includes(search);});
  var c=channels[idx];if(!c)return;
  document.getElementById('ech-pkg').value=c.packageId;
  document.getElementById('ech-id').value=c.id;
  document.getElementById('ech-name').value=c.name||'';
  document.getElementById('ech-grp').value=c.group||'';
  document.getElementById('ech-logo').value=c.logo||'';
  var NL=String.fromCharCode(10);
  var domainsEl=document.getElementById('ech-domains');if(domainsEl)domainsEl.value=(c.domains||[]).join(NL);
  var macsEl=document.getElementById('ech-macs');if(macsEl)macsEl.value=(c.macs||[]).join(NL);
  openM('m-editchmac');
}
async function updateCh(){
  var pkgId=document.getElementById('ech-pkg').value,chId=document.getElementById('ech-id').value;
  var NL=String.fromCharCode(10);
  var updates={name:document.getElementById('ech-name').value,group:document.getElementById('ech-grp').value,logo:document.getElementById('ech-logo').value};
  updates.domains=document.getElementById('ech-domains').value.trim().split(NL).filter(Boolean);
  updates.macs=document.getElementById('ech-macs').value.trim().split(NL).filter(Boolean);
  try{var r=await fetch('/api/channels/update',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({packageId:pkgId,channelId:chId,updates:updates})});var d=await r.json();if(d.success){closeM('m-editchmac');await loadData();sw({icon:'success',title:'تم التحديث',timer:800,showConfirmButton:false});}else sw({icon:'error',title:'خطا',text:d.error});}catch(e){sw({icon:'error',title:'خطا',text:e.message});}
}
async function rotateChannelDomains(){
  var chId=document.getElementById('ech-id').value;if(!chId){sw({icon:'error',title:'لم يتم تحديد قناة'});return;}
  try{var r=await fetch('/api/channels/rotate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({channelId:chId})});var d=await r.json();if(d.success){sw({icon:'success',title:'تم تدوير الدومينات',text:'الدومين: '+d.currentDomain,timer:2000,showConfirmButton:false});}else sw({icon:'error',title:'خطا',text:d.error});}catch(e){sw({icon:'error',title:'خطا',text:e.message});}
}
async function delChById(key){
  var parts=key.split(':'),pkgId=parts[0],chId=parts.slice(1).join(':');
  var ok=await swalConfirm('حذف القناة؟');if(!ok)return;
  try{var r=await fetch('/api/channels/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({packageId:pkgId,channelId:chId})});var d=await r.json();if(d.success){await loadData();sw({icon:'success',title:'تم الحذف',timer:800,showConfirmButton:false});}}catch(e){}
}

// ===== SERVERS =====
function renderServers(){
  var el=document.getElementById('srvslist');if(!el)return;
  if(!D.servers.length){el.innerHTML='<p style="color:#94a3b8;text-align:center;padding:18px">لا توجد خوادم.</p>';return;}
  el.innerHTML='<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:16px">'+D.servers.map(function(s,i){
    var sr=s.totalRequests>0?Math.round(s.successCount/s.totalRequests*100):null;
    var score=D.internal?.scores?.[s.url]||D.internal?.scores?.[new URL(s.url).hostname]||0;
    var srC=sr===null?'#94a3b8':(sr>=80?'#4ade80':(sr>=50?'#fbbf24':'#f87171'));
    var domainsInfo=s.domains&&s.domains.length?'<div style="margin-bottom:8px"><small style="color:#60a5fa">🌐 '+s.domains.length+' دومين</small></div>':'';
    var macsInfo=s.macs&&s.macs.length?'<div style="margin-bottom:8px"><small style="color:#4ade80">🔑 '+s.macs.length+' ماك</small></div>':'';
    var scoreBadge=score>0?'<div style="background:rgba(37,99,235,.2);border:1px solid #2563eb;padding:4px 10px;border-radius:10px;display:flex;align-items:center;gap:6px;font-size:.8rem;color:#60a5fa"><i class="fas fa-arrow-up"></i> '+score+'</div>':'';
    return '<div style="background:linear-gradient(145deg,rgba(15,23,42,.95),rgba(30,41,59,.95));border:2px solid '+(s.active?'#2563eb':'#475569')+';border-radius:14px;padding:18px"><div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:12px"><div><div style="color:#fff;font-weight:700">'+s.name+'</div><div style="font-size:.75rem;color:#64748b">الوزن: '+s.weight+'</div></div><div style="display:flex;flex-direction:column;align-items:flex-end;gap:5px">'+badge(s.active?'badge-ok':'badge-warn',s.active?'نشط':'معطل')+scoreBadge+'</div></div><div style="color:#64748b;font-size:.82rem;direction:ltr;background:rgba(0,0,0,.4);padding:8px;border-radius:8px;margin-bottom:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+s.url+'</div>'+domainsInfo+macsInfo+'<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:12px"><div style="background:rgba(5,150,105,.1);border:1px solid rgba(5,150,105,.3);border-radius:8px;padding:8px;text-align:center"><div style="color:#4ade80;font-weight:700">'+(s.successCount||0)+'</div><div style="color:#64748b;font-size:.72rem">نجاح</div></div><div style="background:rgba(220,38,38,.1);border:1px solid rgba(220,38,38,.3);border-radius:8px;padding:8px;text-align:center"><div style="color:#f87171;font-weight:700">'+(s.failCount||0)+'</div><div style="color:#64748b;font-size:.72rem">فشل</div></div><div style="background:rgba(37,99,235,.1);border:1px solid rgba(37,99,235,.3);border-radius:8px;padding:8px;text-align:center"><div style="color:#60a5fa;font-weight:700">'+(s.totalRequests||0)+'</div><div style="color:#64748b;font-size:.72rem">طلب</div></div></div>'+(sr!==null?'<div style="display:flex;justify-content:space-between;margin-bottom:4px"><span style="color:#94a3b8;font-size:.78rem">معدل النجاح</span><span style="color:'+srC+';font-weight:700">'+sr+'%</span></div><div style="background:#1e293b;border-radius:4px;height:6px;margin-bottom:12px"><div style="width:'+Math.min(sr,100)+'%;background:'+srC+';height:6px;border-radius:4px"></div></div>':'')+'<div style="display:flex;gap:8px"><button class="btn '+(s.active?'bw':'bg')+' bsm" onclick="toggleSrv('+i+')"><i class="fas fa-'+(s.active?'power-off':'play')+'"></i></button><button class="btn bp bsm" style="flex:1" onclick="editSrv('+i+')"><i class="fas fa-edit"></i> تعديل</button><button class="btn br bsm" onclick="delSrv('+i+')"><i class="fas fa-trash"></i></button></div></div>';
  }).join('')+'</div>';
}
async function editSrv(idx){
  var s=D.servers[idx];if(!s)return;
  if(typeof Swal==='undefined'){alert('حمل الصفحة مجددا');return;}
  var domainsStr=(s.domains||[]).join(String.fromCharCode(10));
  var macsStr=(s.macs||[]).join(String.fromCharCode(10));
  Swal.fire({
    title:'تعديل الخادم',
    background:'#020617',
    color:'#fff',
    html:'<div style="text-align:right">'+
      '<label style="color:#94a3b8;display:block;margin-bottom:3px">الاسم</label>'+
      '<input id="esn" class="swal2-input" value="'+s.name+'" style="color:#fff;background:#0f172a">'+
      
      '<label style="color:#94a3b8;display:block;margin-top:8px;margin-bottom:3px">الرابط</label>'+
      '<input id="esu" class="swal2-input" value="'+s.url+'" dir="ltr" style="color:#fff;background:#0f172a">'+
      
      '<label style="color:#94a3b8;display:block;margin-top:8px;margin-bottom:3px">الدومينات (سطر لكل دومين)</label>'+
      '<textarea id="esd" class="swal2-input" rows="3" style="color:#fff;background:#0f172a;resize:vertical;min-height:80px" placeholder="domain1.com&#10;domain2.com">'+domainsStr+'</textarea>'+
      
      '<label style="color:#94a3b8;display:block;margin-top:8px;margin-bottom:3px">الماكات الخاصة (سطر لكل ماك)</label>'+
      '<textarea id="esm" class="swal2-input" rows="3" style="color:#fff;background:#0f172a;resize:vertical;min-height:80px" placeholder="00:1A:79:00:00:00">'+macsStr+'</textarea>'+
      
      '<label style="color:#94a3b8;display:block;margin-top:8px;margin-bottom:3px">الوزن</label>'+
      '<input id="esw" type="number" class="swal2-input" value="'+s.weight+'" min="1" max="10" style="color:#fff;background:#0f172a">'+
      
      '<label style="color:#94a3b8;display:block;margin-top:8px;margin-bottom:3px">الحالة</label>'+
      '<select id="esa" style="width:100%;padding:10px;background:#0f172a;color:#fff;border:1px solid #334155;border-radius:7px">'+
        '<option value="true"'+(s.active?' selected':'')+'>نشط</option>'+
        '<option value="false"'+(!s.active?' selected':'')+'>معطل</option>'+
      '</select>'+
    '</div>',
    showCancelButton:true,
    confirmButtonText:'حفظ',
    cancelButtonText:'الغاء',
    preConfirm:async function(){
      var name=(document.getElementById('esn').value||'').trim(),
          url2=(document.getElementById('esu').value||'').trim(),
          domainsText=(document.getElementById('esd').value||'').trim(),
          macsText=(document.getElementById('esm').value||'').trim();
      if(!name||!url2){
        Swal.showValidationMessage('ادخل الاسم والرابط');
        return false;
      }
      var NL=String.fromCharCode(10);
      var domains=domainsText?domainsText.split(NL).filter(Boolean):[];
      var macs=macsText?macsText.split(NL).filter(Boolean):[];
      D.servers[idx]=Object.assign({},s,{
        name:name,
        url:url2,
        weight:parseInt(document.getElementById('esw').value)||5,
        active:document.getElementById('esa').value==='true',
        domains:domains,
        macs:macs
      });
      var r=await fetch('/api/servers',{
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({servers:D.servers})
      });
      var d=await r.json();
      if(!d.success){
        Swal.showValidationMessage(d.error||'خطا');
        return false;
      }
      return true;
    }
  }).then(function(res){
    if(res.isConfirmed){
      loadData(); // تحميل البيانات من الخادم
      sw({icon:'success',title:'تم التحديث',timer:1000,showConfirmButton:false});
    }
  });
}
async function createSrv(){
  var name=(document.getElementById('ns-name').value||'').trim(),url2=(document.getElementById('ns-url').value||'').trim();
  var wt=parseInt(document.getElementById('ns-wt').value)||5,active=document.getElementById('ns-st').value==='active';
  var NL=String.fromCharCode(10);
  var domains=document.getElementById('ns-domains').value.trim().split(NL).filter(Boolean);
  var macs=document.getElementById('ns-macs').value.trim().split(NL).filter(Boolean);
  if(!name||!url2){sw({icon:'error',title:'ادخل الاسم والرابط'});return;}
  D.servers.push({id:Date.now().toString(),name:name,url:url2,weight:wt,active:active,domains:domains,macs:macs,successCount:0,failCount:0,totalRequests:0,avgResponseTime:0});
  try{
    var r=await fetch('/api/servers',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({servers:D.servers})});
    var d=await r.json();
    if(d.success){
      closeM('m-addsrv');
      await loadData(); // تحميل البيانات من الخادم
      sw({icon:'success',title:'تمت الاضافة',timer:1000,showConfirmButton:false});
    }else{
      sw({icon:'error',title:'خطا',text:d.error});
    }
  }catch(e){sw({icon:'error',title:'خطا',text:e.message});}
}
async function delSrv(idx){var s=D.servers[idx];if(!s)return;var ok=await swalConfirm('حذف الخادم "'+s.name+'"؟');if(!ok)return;D.servers=D.servers.filter(function(x){return x.id!==s.id;});try{await fetch('/api/servers',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({servers:D.servers})});await loadData();sw({icon:'success',title:'تم الحذف',timer:1000,showConfirmButton:false});}catch(e){}}
async function toggleSrv(idx){
  var s=D.servers[idx];if(!s)return;
  s.active = !s.active;
  try{
    var r=await fetch('/api/servers',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({servers:D.servers})});
    var d=await r.json();
    if(d.success){
      renderServers();
      sw({icon:'success',title:s.active?'تم التشغيل':'تم الايقاف',timer:800,showConfirmButton:false});
    }else{
      s.active=!s.active;sw({icon:'error',title:'خطا',text:d.error});
    }
  }catch(e){s.active=!s.active;sw({icon:'error',title:'خطا',text:e.message});}
}
// ===== IMPORT M3U =====
function importPkgM3U(pkgId){_targetPkgM3U=pkgId;document.getElementById('m3ufile-pkg-input').click();}
async function importM3UToTargetPkg(event){
  var file=event.target.files[0];if(!file||!_targetPkgM3U)return;
  sw({title:'جاري المعالجة...',showConfirmButton:false});
  var text=await file.text(),lines=text.split(String.fromCharCode(10)),currentChannel=null;
  if(!D.packages[_targetPkgM3U])return;
  if(!D.packages[_targetPkgM3U].channels)D.packages[_targetPkgM3U].channels=[];
  var baseNum=D.packages[_targetPkgM3U].channels.length;
  for(var i=0;i<lines.length;i++){
    var line=lines[i].trim();
    if(line.startsWith('#EXTINF:')){
      var nameMatch=line.match(/,([^,]+)$/),tvgIdMatch=line.match(/tvg-id="([^"]*)"/),tvgLogoMatch=line.match(/tvg-logo="([^"]*)"/);
      currentChannel={id:tvgIdMatch?tvgIdMatch[1]:('ch_'+Date.now()+'_'+i),name:nameMatch?nameMatch[1].trim():'قناة '+(i+1),url:'',logo:tvgLogoMatch?tvgLogoMatch[1]:'',group:D.packages[_targetPkgM3U].name,packageId:_targetPkgM3U};
    }else if(line.startsWith('http')&&currentChannel){
      currentChannel.url=line;baseNum++;currentChannel.number=baseNum;D.packages[_targetPkgM3U].channels.push(currentChannel);currentChannel=null;
    }
  }
  try{await fetch('/api/packages',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({packages:D.packages})});renderPackages();updateSelects();sw({icon:'success',title:'تمت اضافة القنوات',timer:1500,showConfirmButton:false});}catch(e){sw({icon:'error',title:'خطا',text:e.message});}
  event.target.value='';
}
async function importM3U(event){
  var files=event.target.files; if(!files.length)return;
  var el=document.getElementById('importres');
  el.innerHTML='<p style="color:#60a5fa;text-align:center"><i class="fas fa-spinner fa-spin"></i> جاري معالجة <strong>'+files.length+'</strong> ملفات...</p>';
  var successCount = 0;
  var totalChannels = 0;
  var errors = [];

  for(var i=0; i<files.length; i++){
    var file = files[i];
    var fd = new FormData(); fd.append('file', file);
    try {
      var r = await fetch('/api/upload/m3u', {method:'POST', body:fd});
      var d = await r.json();
      if(d.success) {
        successCount++;
        totalChannels += d.count;
      } else {
        errors.push(file.name + ': ' + d.error);
      }
    } catch(e) {
      errors.push(file.name + ': ' + e.message);
    }
  }

  var resHtml = '<div style="background:rgba(5,150,105,.15);border:1px solid #059669;border-radius:9px;padding:13px;color:#4ade80">' +
    'تم رفع <strong>' + successCount + '</strong> ملفات بنجاح. ' +
    'إجمالي القنوات: <strong>' + totalChannels + '</strong></div>';
  
  if(errors.length > 0) {
    resHtml += '<div style="margin-top:10px;background:rgba(220,38,38,.15);border:1px solid #dc2626;border-radius:9px;padding:13px;color:#f87171">' +
      '<strong>أخطاء في ' + errors.length + ' ملفات:</strong><br><small>' + errors.join('<br>') + '</small></div>';
  }
  
  el.innerHTML = resHtml;
  if(successCount > 0) await loadData();
  event.target.value = '';
}

// ===== PLAYLIST =====
function genPlaylist(){
  var token=document.getElementById('pl-token').value,fmt=document.querySelector('input[name=fmt]:checked').value;
  if(!token){sw({icon:'warning',title:'اختر توكن'});return;}
  var u=window.location.origin+'/playlist.m3u?format='+fmt+'&token='+encodeURIComponent(token);
  document.getElementById('plurl-text').textContent=u;document.getElementById('plresult').style.display='block';
}
function dlPlaylist(){
  var token=document.getElementById('pl-token').value,fmt=document.querySelector('input[name=fmt]:checked').value;
  if(!token){sw({icon:'warning',title:'اختر توكن'});return;}
  window.location.href=window.location.origin+'/playlist.m3u?format='+fmt+'&token='+encodeURIComponent(token);
}
function cpPlaylist(){var txt=document.getElementById('plurl-text').textContent;navigator.clipboard.writeText(txt).then(function(){sw({icon:'success',title:'تم النسخ',timer:800,showConfirmButton:false});});}

loadData();
fetchIP();
`;

  parts.push('<script>' + js + '</' + 'script>');
  parts.push('</body></html>');
  return parts.join('');
}

// ============================================================
// Request Handler (Cloudflare Worker Logic)
// ============================================================

async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;
  const DEFAULT_MACS = [
    "00:1A:79:33:DE:11","00:1A:79:44:BC:22","00:1A:79:55:AA:33","00:1A:79:44:EE:44","00:1A:79:32:00:55",
    "00:1A:79:33:AA:66","00:1A:79:55:00:77","00:1A:79:44:00:88","00:1A:79:22:11:99","00:1A:79:33:BB:00"
  ];

  const CORS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };

  const userAgent = request.headers.get('User-Agent') || '';
  const isTV = userAgent.includes('SMART-TV') || userAgent.includes('WebTV') || userAgent.includes('TV') ||
    userAgent.includes('SmartTV') || userAgent.includes('BRAVIA') || userAgent.includes('LGTV') || userAgent.includes('Vizio');

  if (request.method === 'OPTIONS') return new Response(null, { headers: CORS, status: 204 });
  if (request.method === 'HEAD') return new Response(null, { status: 200, headers: { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/x-mpegurl; charset=utf-8' } });

  // Mock database for Node.js environment
  const db = null;

  if (path === '/api/tokens' && request.method === 'GET') return apiGetTokens(db, CORS);
  if (path === '/api/tokens/create' && request.method === 'POST') return apiCreateToken(request, db, CORS);
  if (path === '/api/tokens/delete' && request.method === 'POST') return apiDeleteToken(request, db, CORS);
  if (path === '/api/tokens/update' && request.method === 'POST') return apiUpdateToken(request, db, CORS);
  if (path === '/api/tokens/validate' && request.method === 'GET') return apiValidateToken(db, CORS, url);
  if (path === '/api/tokens/usage' && request.method === 'GET') return apiGetTokenUsage(db, CORS, url);
  if (path === '/api/tokens/packages/add' && request.method === 'POST') return apiAddPackageToToken(request, db, CORS);
  if (path === '/api/tokens/packages/add-multiple' && request.method === 'POST') return apiAddMultiplePackagesToToken(request, db, CORS);
  if (path === '/api/tokens/packages/remove' && request.method === 'POST') return apiRemovePackageFromToken(request, db, CORS);
  if (path === '/api/tokens/packages/reorder' && request.method === 'POST') return apiReorderTokenPackages(request, db, CORS);
  if (path === '/api/tokens/days/add' && request.method === 'POST') return apiAddDays(request, db, CORS);
  if (path === '/api/tokens/days/remove' && request.method === 'POST') return apiRemoveDays(request, db, CORS);
  if (path === '/api/tokens/block-ip' && request.method === 'POST') return apiBlockIP(request, db, CORS);
  if (path === '/api/tokens/blocked-ips' && request.method === 'GET') return apiGetBlockedIPs(db, CORS, url);

  if (path === '/api/internal/stats' && request.method === 'GET') return await apiGetInternalStats({}, CORS);

  if (path === '/api/macs' && request.method === 'GET') return apiGetMacs(db, CORS, DEFAULT_MACS);
  if (path === '/api/macs' && request.method === 'POST') return apiSaveMacs(request, db, CORS);
  if (path === '/api/macs/update' && request.method === 'POST') return apiUpdateMac(request, db, CORS);
  if (path === '/api/macs/reset-stats' && request.method === 'POST') return apiResetMacStats(request, db, CORS);
  if (path === '/api/macs/list' && request.method === 'GET') return apiGetMacsList(db, CORS, DEFAULT_MACS);
  if (path === '/api/macs/pool' && request.method === 'GET') return apiGetMacPool(db, CORS, DEFAULT_MACS);

  if (path === '/api/packages' && request.method === 'GET') {
    let data = { success: true, data: {} };
    return new Response(JSON.stringify(data), { headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=120", ...CORS } });
  }

  if (path === '/api/packages' && request.method === 'POST') return apiSavePackages(request, db, CORS, {});
  if (path === '/api/packages/update' && request.method === 'POST') return apiUpdatePackage(request, db, CORS, {});
  if (path === '/api/packages/reorder' && request.method === 'POST') return apiReorderGlobalPackages(request, db, CORS, {});
  if (path === '/api/packages/delete-all' && request.method === 'POST') return apiDeleteAllPackages(request, db, CORS, {});
  if (path === '/api/packages/delete' && request.method === 'POST') return apiDeletePackage(request, db, CORS, {});
  if (path === '/api/channels/update' && request.method === 'POST') return apiUpdateChannel(request, db, CORS, {});
  if (path === '/api/channels/delete' && request.method === 'POST') return apiDeleteChannel(request, db, CORS, {});
  if (path === '/api/channels/reorder' && request.method === 'POST') return apiReorderChannels(request, db, CORS, {});
  if (path === '/api/channels/domains' && request.method === 'GET') return apiGetChannelDomains(db, CORS);
  if (path === '/api/channels/domains' && request.method === 'POST') return apiSaveChannelDomains(request, db, CORS);
  if (path === '/api/settings' && request.method === 'GET') return apiGetSettings(db, CORS);
  if (path === '/api/settings' && request.method === 'POST') return apiSaveSettings(request, db, CORS);
  if (path === '/api/channels/macs' && request.method === 'POST') return apiSaveChannelMacs(request, db, CORS);
  if (path === '/api/channels/rotate' && request.method === 'POST') return apiRotateChannelDomains(request, db, CORS);

  if (path === '/api/servers' && request.method === 'GET') return apiGetServers(db, CORS);
  if (path === '/api/servers' && request.method === 'POST') return apiSaveServers(request, db, CORS);
  if (path === '/api/servers/delete' && request.method === 'POST') return apiDeleteServer(request, db, CORS);
  if (path === '/api/stats' && request.method === 'GET') return apiGetStats(db, CORS);
  if (path === '/api/upload/m3u' && request.method === 'POST') return apiUploadM3U(request, db, CORS, {});
  if (path === '/api/debug' && request.method === 'GET') return apiDebug({}, db, CORS);
  if (path === '/api/init-db' && request.method === 'POST') return apiInitDB(db, CORS);
  if (path === '/api/init-servers-columns' && request.method === 'POST') return apiInitServerColumns(db, CORS);
  if (path === '/api/init-channel-columns' && request.method === 'POST') return apiInitChannelColumns(db, CORS);
  if (path === '/api/admin/sync-hardcoded' && request.method === 'POST') return apiSyncHardcoded(db, CORS);
  if (path === '/api/admin/sessions/delete' && request.method === 'POST') return await apiDeleteSession(request, {}, CORS);
  if (path === '/api/admin/sessions/clear' && request.method === 'POST') return await apiClearSessions({}, CORS);

  if (path === '/playlist.m3u' || path === '/playlist.m3u8') return handlePlaylist(url, db, CORS);
  if (path === '/hls-proxy') return handleHLSProxy(request, url, CORS);
  if (path === '/live') return handleUltraLive(request, {}, {});
  if (path === '/epg.xml' || path === '/epg.gz') return handleEPGProxy(CORS);
  if (path.startsWith('/live/')) return handleUltraLive(request, {}, {});

  if (path.startsWith('/live-advanced/')) return handleLiveStreamAdvanced(request, db, CORS);

  if (path === '/' || path === '/panel' || path === '/admin') return renderPanel(url, {}, CORS, DEFAULT_MACS, isTV);

  return Response.redirect(url.origin + '/', 302);
}

// ============================================================
// Render Server Wrapper
// ============================================================

import http from "http";

const PORT = process.env.PORT || 3000;

const server = http.createServer(async (req, res) => {
  try {
    const url = `http://${req.headers.host}${req.url}`;
    const request = new Request(url, {
      method: req.method,
      headers: req.headers
    });

    const response = await handleRequest(request);

    res.writeHead(response.status, Object.fromEntries(response.headers));
    const body = await response.arrayBuffer();
    res.end(Buffer.from(body));

  } catch (err) {
    res.writeHead(500);
    res.end("Server Error: " + err.message);
  }
});

server.listen(PORT, () => {
  console.log("Ultra IPTV Server Running on port", PORT);
});

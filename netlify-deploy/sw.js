const CACHE='bbcx-v10-byok-security';
const FILES=[
  '/manifest.json',
  '/icon-192.png',
  '/icon-512.png'
];

self.addEventListener('install',e=>{
  e.waitUntil(caches.open(CACHE).then(c=>c.addAll(FILES)).then(()=>self.skipWaiting()));
});

self.addEventListener('activate',e=>{
  e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim()));
});

self.addEventListener('fetch',e=>{
  const u=new URL(e.request.url);
  if(u.pathname.startsWith('/api/'))return;
  if(e.request.method!=='GET')return;
  const isPage=e.request.mode==='navigate'||e.request.destination==='document'||u.pathname==='/'||u.pathname==='/index.html';
  if(isPage){
    e.respondWith(
      fetch(e.request,{cache:'no-store'}).catch(()=>new Response('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="theme-color" content="#4A6B62"><title>冰冰出行 · 暂时离线</title><body style="margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:#F8F5F0;color:#1a1a1a;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Microsoft YaHei,sans-serif"><main style="max-width:320px;text-align:center"><p style="font-size:13px;color:#4A6B62">冰冰出行</p><h1 style="font-size:24px;margin:8px 0">暂时没有网络</h1><p style="color:#5F6661;line-height:1.7">输入内容和已保存行程仍在本机。网络恢复后点击下方按钮继续。</p><button onclick="location.reload()" style="min-height:44px;margin-top:18px;padding:0 22px;border:0;border-radius:999px;background:#355E54;color:white;font:inherit;font-weight:700">重新连接</button></main></body></html>',{status:503,statusText:'Offline',headers:{'content-type':'text/html;charset=utf-8','cache-control':'no-store'}}))
    );
    return;
  }
  e.respondWith(
    caches.match(e.request).then(async cached=>{
      const update=fetch(e.request).then(async r=>{if(r.ok){const c=await caches.open(CACHE);await c.put(e.request,r.clone())}return r});
      if(cached){e.waitUntil(update.catch(()=>{}));return cached}
      return update;
    }).catch(()=>new Response('',{status:504,statusText:'Offline'}))
  );
});

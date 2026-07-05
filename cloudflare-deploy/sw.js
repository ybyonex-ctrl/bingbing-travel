const CACHE='bbcx-v3';
const FILES=['/manifest.json','/icon-192.png','/icon-512.png'];

self.addEventListener('install',e=>{
  e.waitUntil(caches.open(CACHE).then(c=>c.addAll(FILES)).then(()=>self.skipWaiting()));
});

self.addEventListener('activate',e=>{
  e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim()));
});

self.addEventListener('fetch',e=>{
  const u=new URL(e.request.url);
  if(u.pathname.startsWith('/api/'))return;
  const isPage=e.request.mode==='navigate'||e.request.destination==='document'||u.pathname==='/'||u.pathname==='/index.html';
  if(isPage){
    e.respondWith(
      fetch(e.request).then(r=>{
        if(r.ok){const clone=r.clone();caches.open(CACHE).then(c=>c.put(e.request,clone))}
        return r;
      }).catch(()=>caches.match(e.request).then(cached=>cached||caches.match('/index.html')||caches.match('/')))
    );
    return;
  }
  e.respondWith(
    caches.match(e.request).then(cached=>{
      const fetched=fetch(e.request).then(r=>{if(r.ok){const clone=r.clone();caches.open(CACHE).then(c=>c.put(e.request,clone))}return r});
      return cached||fetched;
    })
  );
});

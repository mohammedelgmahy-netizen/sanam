// opens from the phone's copy right away and refreshes it in the background; data always comes live from Supabase
const C="sanam-v6",SHELL=["./","index.html","manifest.webmanifest","icon-192.png","icon-512.png","icon-maskable-512.png"];
self.addEventListener("install",e=>{e.waitUntil(caches.open(C).then(c=>c.addAll(SHELL)));self.skipWaiting()});
self.addEventListener("activate",e=>{e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x.startsWith("sanam-")&&x!==C).map(x=>caches.delete(x)))));self.clients.claim()});
self.addEventListener("fetch",e=>{const u=new URL(e.request.url);if(e.request.method!=="GET"||u.hostname.endsWith("supabase.co"))return;
  const mine=u.origin===location.origin&&u.pathname.startsWith(new URL("./",location).pathname);
  if(!mine&&!/cdn|fonts/.test(u.hostname))return;
  e.respondWith(caches.open(C).then(async c=>{const hit=await c.match(e.request,{ignoreSearch:mine});
    const net=fetch(e.request).then(r=>{if(r.ok||r.type==="opaque")c.put(e.request,r.clone());return r}).catch(()=>hit);
    if(hit){e.waitUntil(net);return hit}return net}))});

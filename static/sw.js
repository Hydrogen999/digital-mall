// A minimal Service Worker to enable PWA installation
self.addEventListener('install', (e) => {
  self.skipWaiting();
});

self.addEventListener('fetch', (e) => {
  // We just let the network handle everything for now (no offline caching yet)
  e.respondWith(fetch(e.request).catch(() => caches.match(e.request)));
});
// Service Worker del POS: solo maneja notificaciones push.
// No cachea nada (a propósito: la app ya maneja su propio guardado offline
// vía localStorage, duplicar la lógica de caché acá solo agregaría bugs).

self.addEventListener('install', (event) => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('push', (event) => {
  let data = { title: 'POS', body: 'Nueva notificación' };
  try {
    if (event.data) data = event.data.json();
  } catch (e) {
    if (event.data) data = { title: 'POS', body: event.data.text() };
  }
  const opciones = {
    body: data.body || '',
    vibrate: [200, 100, 200],
    tag: 'pos-venta', // agrupa notificaciones seguidas en vez de apilarlas
  };
  event.waitUntil(self.registration.showNotification(data.title || 'POS', opciones));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(self.clients.openWindow('/'));
});

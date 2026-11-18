/* TerminalChat service worker — shows real OS notifications (Windows / Android / iOS home-screen app)
 * when the server sends a push, even if the tab is in the background or closed.
 * It contains no secrets. It must be its own file because browsers only allow service workers from a file. */
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

self.addEventListener('push', (event) => {
  let d = {};
  try { d = event.data ? event.data.json() : {}; } catch { d = {}; }
  event.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    // If the chat is open and in front of you, the page already shows the message — no notification needed.
    if (wins.some((c) => c.focused && c.visibilityState === 'visible')) return;
    await self.registration.showNotification(String(d.title || 'TerminalChat'), {
      body: String(d.body || ''),
      tag: d.tag || undefined,          // same tag = the page and the push never show the same message twice
      data: { scope: d.scope, roomId: d.roomId, from: d.from },
    });
  })());
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const data = event.notification.data || {};
  event.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    if (wins.length) {
      const w = wins[0];
      await w.focus();
      w.postMessage({ type: 'open', ...data });
      return;
    }
    const hash = data.scope === 'dm' && data.from ? `#dm=${encodeURIComponent(data.from)}` : data.roomId ? `#room=${encodeURIComponent(data.roomId)}` : '';
    await self.clients.openWindow(self.registration.scope + hash);
  })());
});

// Run with: ~/.bun/bin/bun server.js
const htmlPath = new URL('./index.html', import.meta.url);

Bun.serve({
  port: 3000,
  async fetch(req) {
    const url = new URL(req.url);

    if (url.pathname === '/') {
      return new Response(Bun.file(htmlPath), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    if (url.pathname.startsWith('/api/cgr/')) {
      const pkg = url.pathname.slice('/api/cgr/'.length);
      const user = req.headers.get('x-cgr-user') || '';
      const pass = req.headers.get('x-cgr-pass') || '';

      const upstream = `https://libraries.cgr.dev/javascript/${pkg}`;
      const headers = {};
      if (user) {
        headers['Authorization'] = 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64');
      }

      try {
        const res = await fetch(upstream, { headers });
        const body = await res.text();
        return new Response(body, {
          status: res.status,
          headers: { 'Content-Type': 'application/json' },
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), {
          status: 502,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    }

    return new Response('Not found', { status: 404 });
  },
});

console.log('Listening on http://localhost:3000');

process.on('SIGTERM', () => process.exit(0));
process.on('SIGINT', () => process.exit(0));

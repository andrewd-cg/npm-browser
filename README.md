# npm-browser

A local single-page tool to compare npm package versions across **npmjs.com** and the **Chainguard registry** (`libraries.cgr.dev`).

Enter a package name and get a side-by-side table showing which versions are available in each registry, whether they were built by Chainguard or mirrored from upstream, and when each version was published.

## Features

- Side-by-side version comparison: npmjs.com vs Chainguard
- Built vs Secure Mirror badge per Chainguard version
- Coverage summary: % of versions in Chainguard, broken down by Built vs Mirrored
- Publish date + days ago for each version
- Pre-release versions hidden by default (alpha, beta, canary, rc)
- Limit to 50 most recent versions by default
- Copy results as formatted plain text for sharing in Slack or a text editor
- Credentials stored locally in browser `localStorage` — nothing is sent anywhere except the two registries

## Requirements

[Bun](https://bun.sh) — a local proxy server is needed to forward authenticated requests to `libraries.cgr.dev` and avoid CORS restrictions.

```bash
curl -fsSL https://bun.sh/install | bash
```

## Start

```bash
./start.sh
```

Then open [http://localhost:3000](http://localhost:3000) in your browser.

## Configuration

To get credentials for `libraries.cgr.dev`, run:

```bash
chainctl auth pull-token --repository=javascript [--parent=andrewd.dev]
```

Copy the username and password from the output, then click the **gear icon** (top right) and paste them into the Username and Password fields. Credentials are saved in your browser's `localStorage` under `npm-browser-cgr-user` and `npm-browser-cgr-pass` and are only ever sent to your local proxy server.

## How it works

```
Browser → GET /api/cgr/<package> → server.js → libraries.cgr.dev (Basic Auth)
Browser → GET registry.npmjs.org/<package> (direct, CORS supported)
```

`server.js` is a minimal [Bun](https://bun.sh) HTTP server with two responsibilities:
- Serve `index.html`
- Proxy requests to `libraries.cgr.dev` with `Authorization: Basic` headers to work around browser CORS restrictions

All UI logic lives in `index.html` — no build step, no dependencies.

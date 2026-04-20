# npm-browser

A simple tool to compare npm package versions across **npmjs.com** and the **Chainguard registry** (`libraries.cgr.dev`).

Enter a package name and get a side-by-side table showing which versions are available in each registry, whether they were built by Chainguard or mirrored from upstream, and when each version was published.

## Features

- Side-by-side version comparison: npmjs.com vs Chainguard
- Built vs Secure Mirror badge per Chainguard version
- Coverage summary: % of versions in Chainguard, broken down by Built vs Mirrored
- Publish date + days ago for each version
- Pre-release versions hidden by default (alpha, beta, canary, rc)
- Limit to 50 most recent versions by default
- Copy results as formatted plain text for sharing in Slack or a text editor
- Credentials stored locally in browser `localStorage` — nothing is sent anywhere except for libraries.cgr.dev

## Start

### Option 1: Docker

```bash
docker run -p 3000:3000 ghcr.io/andrewd-chainguard/npm-browser:latest
```

### Option 2: Bun

Requires [Bun](https://bun.sh):

```bash
curl -fsSL https://bun.sh/install | bash
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


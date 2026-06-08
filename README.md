# Domain Footprint Atlas

Passive browser-based OSINT atlas for mapping a public domain footprint from public, unauthenticated sources.

Live site: https://danzaio.github.io/domain-footprint-atlas/
Repository: https://github.com/danzaio/domain-footprint-atlas

## What it does

Domain Footprint Atlas runs entirely in the browser. It normalizes a domain, queries passive public sources, and builds a typed report with source URLs, timestamps, warnings, and client-side exports.

| Area | Capability | Source or implementation | Notes |
| --- | --- | --- | --- |
| DNS | Looks up `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `SOA`, and `CAA` records. | Cloudflare DNS over HTTPS JSON API in `src/lib/sources.ts`. | Results are parsed into typed report sections and preserved independently when another source fails. |
| RDAP | Summarizes domain registration metadata. | `https://rdap.org/domain/{domain}`. | Includes registrar, events, nameservers, status values, and raw source URL references where available. |
| IP RDAP | Resolves network ownership metadata for DNS-returned IPs. | `https://rdap.org/ip/{ip}`. | Runs only for IPs discovered from DNS answers. No network probing is performed. |
| CT and subdomains | Collects certificate transparency rows and subdomain candidates. | Cert Spotter public unauthenticated CT endpoint. | Dedupe keeps the report useful even when CT data is noisy or partially unavailable. |
| GitHub recipes | Provides manual GitHub footprint search links. | Static recipe generation in the browser. | No GitHub token, scraping, authenticated API, or repository crawling. |
| Localization | Supports `pt-BR` and `en-US`. | Dictionaries in `src/lib/i18n.ts`. | Defaults from `navigator.language`, persists the selected locale in `localStorage`, and updates the document language. |
| Export | Exports JSON and Markdown reports. | Client-side export helpers in `src/lib/atlas.ts` and UI actions in `src/App.tsx`. | Exports include source metadata, warnings, and passive-only disclaimer text. |
| Deployment | Ships as a static Vite app. | GitHub Pages branch publishing from `gh-pages` branch root. | No backend, serverless function, proxy, database, or secret store is required. |

## Safety model

This project is passive-only:

- No port scanning.
- No crawling.
- No backend.
- No proxy.
- No server actions.
- No secrets.
- No authenticated GitHub API.
- No private DanOS data.

The app only requests public browser-reachable endpoints selected for passive domain footprinting. Public source availability and rate limits can produce partial reports. Panels preserve successful source results when another source fails.

## Browser and source limitations

Domain Footprint Atlas intentionally runs without a backend. That keeps the deployment auditable as a static site and avoids collecting submitted domains, storing results, handling secrets, or operating a proxy that could be mistaken for a scanning service.

This model has practical limits:

- Browser CORS rules decide which public endpoints can be queried directly. A source that does not allow browser access cannot be used safely without adding a backend or proxy.
- Public unauthenticated endpoints can rate limit, change response shape, reject requests, or be temporarily unavailable.
- Reports can be partial. DNS may succeed while RDAP, IP RDAP, CT, or another source fails.
- Client networks, browser extensions, privacy tools, or corporate filters can block specific source requests.
- GitHub footprinting is recipe-based. The app generates search links for the user to open manually instead of calling authenticated GitHub APIs or scraping results.

Warnings are surfaced in the report instead of hiding failures. A partial report is expected behavior when one public source is unavailable.

## Repository structure

Key paths:

```text
README.md                 Public project documentation.
package.json              npm scripts for development, verification, and build.
vite.config.ts            Vite configuration, including GitHub Pages base path.
src/App.tsx               Main application shell and section rendering.
src/App.css               Application styling.
src/lib/atlas.ts          Report data types, normalization, parsing, and export helpers.
src/lib/sources.ts        Browser source adapters for DNS, RDAP, IP RDAP, CT, and GitHub recipes.
src/lib/i18n.ts           `pt-BR` and `en-US` localization dictionaries.
src/**/*.test.ts          Unit tests for parsing, localization, export, and partial-source behavior.
```

App sections are Overview, DNS, RDAP, Certificates, GitHub footprint, Timeline, and Export.

## Localization

The UI supports:

- `pt-BR`
- `en-US`

The app defaults to `pt-BR` when `navigator.language` starts with `pt`; otherwise it defaults to `en-US`. The selected locale is persisted in `localStorage`, and the document language is updated when toggled.

## Development

Requirements:

- Node.js and npm.

Install dependencies and start the Vite dev server:

```bash
npm install
npm run dev
```

## Verification

```bash
npm run lint
npm run typecheck
npm run test -- --run
npm run build
```

Or run the full local gate:

```bash
npm run verify
```

Pure logic tests cover:

- Domain normalization and rejection.
- Dictionary fallback and key coverage.
- DNS response parsing.
- RDAP summary extraction.
- Certificate transparency subdomain dedupe.
- Markdown export content.
- Partial-source failure preserving successful panels.

## Deployment

Current production deployment uses GitHub Pages branch publishing:

- Source branch: `gh-pages`
- Source path: `/`
- Published URL: https://danzaio.github.io/domain-footprint-atlas/

The Vite project base is fixed to `/domain-footprint-atlas/` in `vite.config.ts` for GitHub Pages project hosting.

To publish the current build manually:

```bash
npm run verify
npm run build
```

Then copy the built `dist/` contents to the root of the `gh-pages` branch and push that branch.

GitHub Actions deployment is not part of the current production setup. If workflow-based deployment is added later, the GitHub credential used to push `.github/workflows/*.yml` must include the `workflow` scope. Without that scope, GitHub rejects workflow file updates even when ordinary repository pushes work.

Do not add secrets for the current static deployment. The app does not need API keys, a backend URL, or authenticated service credentials.

## License

MIT

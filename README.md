# Domain Footprint Atlas

Passive browser-based OSINT atlas for mapping a public domain footprint.

Live site: https://danzaio.github.io/domain-footprint-atlas/
Repository: https://github.com/danzaio/domain-footprint-atlas

## What it does

Domain Footprint Atlas runs entirely in the browser and builds a typed report from public passive sources:

- DNS records via Cloudflare DNS over HTTPS JSON for `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `SOA`, and `CAA`.
- Domain registration metadata via `rdap.org/domain/{domain}`.
- Network ownership metadata via `rdap.org/ip/{ip}` for DNS-returned IPs.
- Certificate transparency rows and subdomain candidates via Cert Spotter public unauthenticated CT endpoint.
- GitHub footprint recipes as manual search links. No GitHub token, scraping, or authenticated API calls.
- Client-side JSON and Markdown export with source URLs, timestamps, warnings, and passive-only disclaimer.

## Safety model

This project is passive-only:

- No port scanning.
- No crawling.
- No backend.
- No server actions.
- No secrets.
- No authenticated GitHub API.
- No private DanOS data.

Public source availability and rate limits can produce partial reports. Panels preserve successful source results when another source fails.

## Localization

The UI supports:

- `pt-BR`
- `en-US`

The app defaults to `pt-BR` when `navigator.language` starts with `pt`; otherwise it defaults to `en-US`. The selected locale is persisted in `localStorage`, and the document language is updated when toggled.

## Development

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

Then copy `dist/` to the `gh-pages` branch and push it.

GitHub Actions deployment can be added later, but the active local GitHub OAuth credential must include the `workflow` scope before pushing `.github/workflows/*.yml`.

## License

MIT

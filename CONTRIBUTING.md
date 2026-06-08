# Contributing

Thanks for helping improve Domain Footprint Atlas, a passive browser-based OSINT atlas for public domain footprint mapping.

## Setup

Use npm from the repository root.

```bash
npm install
npm run dev
```

The local Vite server prints the development URL in the terminal.

## Local verification

Run focused checks before opening a pull request:

```bash
npm run lint
npm run typecheck
npm run test -- --run
npm run build
```

Or run the combined local gate:

```bash
npm run verify
```

## Coding expectations

- Keep the app static and browser-only.
- Prefer small, typed, pure functions for parsing and normalization.
- Keep UI behavior deterministic and easy to test.
- Preserve partial results when one public source fails.
- Surface source URLs, timestamps, and warnings clearly in exported reports.
- Avoid adding dependencies unless they materially reduce risk or complexity.
- Do not add secrets, tokens, server actions, backend endpoints, proxy services, or telemetry.

## Tests

Add or update tests for pure logic when changing:

- Domain normalization and validation.
- DNS response parsing.
- RDAP extraction.
- Certificate transparency parsing or deduplication.
- Export formatting.
- Locale dictionaries and translation key coverage.
- Partial-source failure handling.

Tests should verify behavior and edge cases, not implementation details.

## Passive-only constraints

Contributions must not introduce:

- Port scanning.
- Crawling or spidering.
- Brute forcing.
- Login flows.
- Authenticated API calls.
- Secret storage.
- Backend services.
- Collection of private DanOS data or private third-party data.

Allowed integrations are public, unauthenticated, passive sources and manual search links that the user opens intentionally.

## Internationalization

Visible user-facing strings must be available in both `en-US` and `pt-BR`. Keep locale keys aligned and update tests when translation coverage changes.

## Pull request checklist

Before requesting review, confirm that:

- The change preserves the passive-only static browser model.
- No secrets, backend code, authenticated APIs, crawlers, or scanners were added.
- User-facing strings are present in both `en-US` and `pt-BR`.
- Relevant pure logic tests were added or updated.
- `npm run lint`, `npm run typecheck`, `npm run test -- --run`, and `npm run build` pass locally, or the PR clearly explains why a command could not be run.
- The live GitHub Pages deployment from `gh-pages` keeps the `/domain-footprint-atlas/` base path compatible.
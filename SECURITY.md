# Security Policy

## Supported versions

Domain Footprint Atlas currently supports the `1.x` release line.

| Version | Supported |
| --- | --- |
| 1.x | Yes |
| < 1.0 | No |

## Security model

Domain Footprint Atlas is a passive, static browser tool for public OSINT workflows.

The project must remain:

- No backend services.
- No stored secrets or API keys.
- No authenticated APIs.
- No port scanning.
- No crawling.
- No active probing of target infrastructure.
- No private data collection.

The app may request public, unauthenticated data from passive sources such as DNS over HTTPS, RDAP, certificate transparency endpoints, and manually opened public search links. Reports are generated client-side in the browser.

## Reporting a vulnerability

If the issue is non-sensitive, open a GitHub issue with:

- A clear description of the problem.
- Steps to reproduce.
- Expected and actual behavior.
- Browser and operating system details when relevant.
- Whether the issue could expose user data, secrets, or target data.

For sensitive reports, use GitHub Security Advisories private vulnerability reporting if it is enabled for this repository. If private reporting is not available, avoid posting exploit details publicly and contact the repository owner through the contact methods listed on the GitHub profile or repository metadata.

## Responsible disclosure

Please:

- Do not attack third-party domains while testing this project.
- Do not run scans, crawlers, brute force tools, or authenticated probes against targets from the app.
- Do not submit real secrets, private tokens, customer data, or private infrastructure details in reports.
- Give maintainers reasonable time to review and fix confirmed vulnerabilities before public disclosure.
- Share only the minimum proof needed to demonstrate the issue.

Reports about passive-source outages, rate limits, stale public records, or incomplete public data are usually reliability issues, not security vulnerabilities.
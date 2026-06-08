import { describe, expect, it } from 'vitest'
import type { DomainReport, EvidenceSource, SourceResult } from './atlas'
import { normalizeDomain } from './atlas'
import { reportToMarkdown } from './exporters'
import { dictionaries, detectLocale, locales, translate } from './i18n'
import {
  buildGithubQueries,
  extractSubdomains,
  parseCertificateSummaries,
  parseDnsResponse,
  summarizeRdapDomain,
} from './sources'

const source: EvidenceSource = {
  id: 'fixture',
  name: 'Fixture',
  url: 'https://example.test',
  descriptionKey: 'source.cloudflare',
}

function result<T>(data: T, status: SourceResult<T>['status'] = 'success', error?: string): SourceResult<T> {
  return { data, status, error, queriedAt: '2026-06-08T00:00:00.000Z', source }
}

describe('normalizeDomain', () => {
  it('strips protocol, path, port, trailing dot, and casing', () => {
    expect(normalizeDomain('HTTPS://Example.COM:443/a?b#c.')).toEqual({ ok: true, domain: 'example.com' })
  })

  it('rejects empty, IP, localhost, and invalid domains', () => {
    expect(normalizeDomain('').errorKey).toBe('empty')
    expect(normalizeDomain('192.0.2.1').errorKey).toBe('ipAddress')
    expect(normalizeDomain('localhost').errorKey).toBe('localhost')
    expect(normalizeDomain('bad_domain').errorKey).toBe('invalidDomain')
  })
})

describe('i18n dictionaries', () => {
  it('detects Portuguese browser locales and falls back to English otherwise', () => {
    expect(detectLocale('pt-BR')).toBe('pt-BR')
    expect(detectLocale('en-GB')).toBe('en-US')
  })

  it('keeps both locales on the same key set', () => {
    const enKeys = Object.keys(dictionaries['en-US']).sort()
    for (const locale of locales) {
      expect(Object.keys(dictionaries[locale]).sort()).toEqual(enKeys)
      expect(translate(locale, 'app.title')).toBeTruthy()
    }
  })
})

describe('source parsing', () => {
  it('parses DNS answers and normalizes MX priority', () => {
    expect(
      parseDnsResponse('MX', {
        Answer: [{ name: 'example.com.', type: 15, TTL: 300, data: '10 mail.example.com.' }],
      }),
    ).toEqual([{ type: 'MX', name: 'example.com', value: 'mail.example.com', ttl: 300, priority: 10 }])
  })
  it('decodes RFC3597 CAA records into readable issue tags', () => {
    expect(
      parseDnsResponse('CAA', {
        Answer: [
          {
            name: 'example.com.',
            type: 257,
            TTL: 300,
            data: '\\# 19 00 05 69 73 73 75 65 64 69 67 69 63 65 72 74 2e 63 6f 6d',
          },
        ],
      }),
    ).toEqual([
      {
        type: 'CAA',
        name: 'example.com',
        value: '0 issue "digicert.com"',
        ttl: 300,
        rawValue: '\\# 19 00 05 69 73 73 75 65 64 69 67 69 63 65 72 74 2e 63 6f 6d',
      },
    ])
  })

  it('parses Null MX answers explicitly with zero priority', () => {
    expect(
      parseDnsResponse('MX', {
        Answer: [{ name: 'example.com.', type: 15, TTL: 300, data: '0 .' }],
      }),
    ).toEqual([{ type: 'MX', name: 'example.com', value: 'Null MX (0 .)', ttl: 300, priority: 0 }])
  })

  it('summarizes RDAP domain data', () => {
    const summary = summarizeRdapDomain({
      handle: '2336799_DOMAIN_COM-VRSN',
      ldhName: 'EXAMPLE.COM',
      status: ['active'],
      events: [
        { eventAction: 'last changed', eventDate: '2024-01-02T00:00:00Z' },
        { eventAction: 'registration', eventDate: '1995-08-14T04:00:00Z' },
      ],
      nameservers: [{ ldhName: 'A.IANA-SERVERS.NET' }, { ldhName: 'a.iana-servers.net' }],
      entities: [
        {
          handle: 'registrar-1',
          roles: ['registrar'],
          vcardArray: ['vcard', [['fn', {}, 'text', 'Example Registrar']]],
        },
      ],
      links: [{ href: 'https://rdap.example.test/domain/example.com' }],
    })

    expect(summary.registrar).toBe('Example Registrar')
    expect(summary.events).toEqual([
      { action: 'registration', date: '1995-08-14T04:00:00Z' },
      { action: 'last changed', date: '2024-01-02T00:00:00Z' },
    ])
    expect(summary.nameservers).toEqual(['a.iana-servers.net'])
  })

  it('returns no certificates for non-array input and skips malformed certificate entries', () => {
    expect(parseCertificateSummaries({ dns_names: ['www.example.com'] }, 'example.com')).toEqual([])

    expect(() => parseCertificateSummaries([null, false, 'bad', 42], 'example.com')).not.toThrow()
    expect(
      parseCertificateSummaries(
        [null, false, 'bad', 42, { id: 'valid', dns_names: ['www.example.com'], issuer: { name: 'Fixture CA' } }],
        'example.com',
      ),
    ).toMatchObject([{ id: 'valid', dnsNames: ['www.example.com'], issuer: 'Fixture CA' }])
  })
  it('preserves Cert Spotter cert_sha256 fallback hashes for export', () => {
    const hash = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    const certificates = parseCertificateSummaries(
      [{ id: 'cert-sha256-only', dns_names: ['example.com'], issuer: { name: 'Fixture CA' }, cert_sha256: hash }],
      'example.com',
    )

    expect(certificates).toMatchObject([{ id: 'cert-sha256-only', certDerSha256: hash, certSha256: hash }])

    const report: DomainReport = {
      domain: 'example.com',
      generatedAt: '2026-06-08T00:00:00.000Z',
      sources: [source],
      dns: result([]),
      rdap: result(null),
      ipRdap: result([]),
      certificates: result(certificates),
      subdomains: [],
      githubQueries: [],
      warnings: [],
    }

    const markdown = reportToMarkdown(report, 'en-US')
    expect(markdown).toContain(`SHA256: ${hash}`)
    expect(markdown).not.toContain('SHA256: n/a')
  })
  it('dedupes CT subdomains from certificate DNS names', () => {
    const certs = parseCertificateSummaries(
      [
        { id: '1', dns_names: ['www.example.com', '*.api.example.com', 'other.test'] },
        { id: '2', dns_names: ['WWW.example.com', 'example.com'] },
      ],
      'example.com',
    )

    expect(extractSubdomains('example.com', certs)).toEqual(['api.example.com', 'example.com', 'www.example.com'])
  })
})

describe('exports and partial failures', () => {
  it('includes source URLs, warnings, timestamps, and GitHub queries in Markdown', () => {
    const report: DomainReport = {
      domain: 'example.com',
      generatedAt: '2026-06-08T00:00:00.000Z',
      sources: [source],
      dns: result([{ type: 'A', name: 'example.com', value: '93.184.216.34', ttl: 300 }]),
      rdap: result(null, 'error', 'RDAP unavailable'),
      ipRdap: result([]),
      certificates: result([], 'warning', 'Cert Spotter is rate-limited.'),
      subdomains: [],
      githubQueries: buildGithubQueries('example.com'),
      warnings: ['RDAP unavailable', 'Cert Spotter is rate-limited.'],
    }

    const markdown = reportToMarkdown(report, 'en-US')
    expect(markdown).toContain('2026-06-08T00:00:00.000Z')
    expect(markdown).toContain('https://example.test')
    expect(markdown).toContain('RDAP unavailable')
    expect(markdown).toContain('filename:.env "example.com"')
  })
  it('includes external manual links in Markdown exports when present', () => {
    const report: DomainReport = {
      domain: 'example.com',
      generatedAt: '2026-06-08T00:00:00.000Z',
      sources: [source],
      dns: result([]),
      rdap: result(null),
      ipRdap: result([]),
      certificates: result([]),
      subdomains: [],
      githubQueries: [],
      externalManualLinks: [
        {
          id: 'crtsh',
          labelKey: 'link.crtsh',
          display: 'example.com',
          url: 'https://crt.sh/?q=example.com',
        },
      ],
      warnings: [],
    }

    const markdown = reportToMarkdown(report, 'en-US')
    expect(markdown).toContain('- External searches: 1')
    expect(markdown).toContain('Open crt.sh manually: `example.com`')
    expect(markdown).toContain('https://crt.sh/?q=example.com')
  })

  it('preserves successful panels when another source fails', () => {
    const report: DomainReport = {
      domain: 'example.com',
      generatedAt: '2026-06-08T00:00:00.000Z',
      sources: [source],
      dns: result([{ type: 'A', name: 'example.com', value: '93.184.216.34', ttl: 300 }]),
      rdap: result(null, 'error', 'RDAP unavailable'),
      ipRdap: result([{ ip: '93.184.216.34', name: 'EDGECAST', links: [] }]),
      certificates: result([]),
      subdomains: [],
      githubQueries: buildGithubQueries('example.com'),
      warnings: ['RDAP unavailable'],
    }

    expect(report.dns.status).toBe('success')
    expect(report.dns.data).toHaveLength(1)
    expect(report.rdap.status).toBe('error')
    expect(report.ipRdap.data[0]?.name).toBe('EDGECAST')
  })
})

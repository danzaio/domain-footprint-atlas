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

  it('summarizes RDAP domain data', () => {
    const summary = summarizeRdapDomain({
      handle: '2336799_DOMAIN_COM-VRSN',
      ldhName: 'EXAMPLE.COM',
      status: ['active'],
      events: [{ eventAction: 'registration', eventDate: '1995-08-14T04:00:00Z' }],
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
    expect(summary.events).toEqual([{ action: 'registration', date: '1995-08-14T04:00:00Z' }])
    expect(summary.nameservers).toEqual(['a.iana-servers.net'])
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

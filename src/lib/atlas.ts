export type SourceStatus = 'idle' | 'loading' | 'success' | 'warning' | 'error'

export type DnsType = 'A' | 'AAAA' | 'CNAME' | 'MX' | 'NS' | 'TXT' | 'SOA' | 'CAA'

export interface EvidenceSource {
  id: string
  name: string
  url: string
  descriptionKey: string
}

export interface SourceResult<T> {
  status: SourceStatus
  data: T
  error?: string
  queriedAt: string
  source: EvidenceSource
  metadata?: SourceResultMetadata
}

export interface SourceResultMetadata {
  returnedCount?: number
  caveat?: string
}

export interface DnsRecord {
  type: DnsType
  name: string
  value: string
  ttl?: number
  priority?: number
  rawValue?: string
}

export interface RdapEntity {
  handle?: string
  roles: string[]
  name?: string
}

export interface RdapSummary {
  handle?: string
  name?: string
  status: string[]
  registrar?: string
  country?: string
  events: Array<{ action: string; date: string }>
  nameservers: string[]
  entities: RdapEntity[]
  links: string[]
}

export interface IpRdapSummary {
  ip: string
  handle?: string
  name?: string
  country?: string
  startAddress?: string
  endAddress?: string
  links: string[]
}

export interface CertificateSummary {
  id: string
  dnsNames: string[]
  issuer?: string
  notBefore?: string
  notAfter?: string
  certDerSha256?: string
  certSha256?: string
  tbsSha256?: string
  sourceUrl: string
}

export interface GithubQuery {
  id: string
  labelKey: string
  query: string
  url: string
}

export interface ExternalManualLink {
  id: string
  labelKey: string
  url: string
  display: string
}

export interface DomainReport {
  domain: string
  generatedAt: string
  sources: EvidenceSource[]
  dns: SourceResult<DnsRecord[]>
  rdap: SourceResult<RdapSummary | null>
  ipRdap: SourceResult<IpRdapSummary[]>
  certificates: SourceResult<CertificateSummary[]>
  subdomains: string[]
  githubQueries: GithubQuery[]
  externalManualLinks?: ExternalManualLink[]
  warnings: string[]
}

export interface NormalizedDomainResult {
  ok: boolean
  domain: string
  errorKey?: 'empty' | 'ipAddress' | 'invalidDomain' | 'localhost'
}

const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/
const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/

export function normalizeDomain(input: string): NormalizedDomainResult {
  const trimmed = input.trim()
  if (!trimmed) return { ok: false, domain: '', errorKey: 'empty' }

  let candidate = trimmed.toLowerCase()
  candidate = candidate.replace(/^[a-z][a-z0-9+.-]*:\/\//, '')
  candidate = candidate.replace(/^[^@/]+@/, '')
  candidate = candidate.split(/[/?#]/, 1)[0] ?? ''
  candidate = candidate.replace(/:\d+$/, '')
  candidate = candidate.replace(/\.$/, '')

  if (!candidate) return { ok: false, domain: '', errorKey: 'empty' }
  if (candidate === 'localhost') return { ok: false, domain: candidate, errorKey: 'localhost' }
  if (IPV4_RE.test(candidate) || candidate.includes(':')) {
    return { ok: false, domain: candidate, errorKey: 'ipAddress' }
  }
  if (!DOMAIN_RE.test(candidate)) return { ok: false, domain: candidate, errorKey: 'invalidDomain' }
  return { ok: true, domain: candidate }
}

export function uniqueSorted(values: Iterable<string>): string[] {
  return [...new Set([...values].map((value) => value.toLowerCase()).filter(Boolean))].sort((a, b) =>
    a.localeCompare(b),
  )
}

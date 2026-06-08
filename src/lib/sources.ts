import type {
  CertificateSummary,
  DnsRecord,
  DnsType,
  DomainReport,
  EvidenceSource,
  GithubQuery,
  IpRdapSummary,
  RdapEntity,
  RdapSummary,
  SourceResult,
} from './atlas'
import { uniqueSorted } from './atlas'

const DNS_TYPES: DnsType[] = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA']
const CLOUDFLARE_DOH = 'https://cloudflare-dns.com/dns-query'
const RDAP_DOMAIN_BASE = 'https://rdap.org/domain/'
const RDAP_IP_BASE = 'https://rdap.org/ip/'
const CERT_SPOTTER_BASE = 'https://api.certspotter.com/v1/issuances'
const TIMEOUT_MS = 12_000

export const sourceCatalog = {
  dns: {
    id: 'cloudflare-doh',
    name: 'Cloudflare DNS over HTTPS',
    url: CLOUDFLARE_DOH,
    descriptionKey: 'source.cloudflare',
  },
  rdap: {
    id: 'rdap-domain',
    name: 'RDAP domain registry',
    url: RDAP_DOMAIN_BASE,
    descriptionKey: 'source.rdapDomain',
  },
  ipRdap: {
    id: 'rdap-ip',
    name: 'RDAP network registry',
    url: RDAP_IP_BASE,
    descriptionKey: 'source.rdapIp',
  },
  certs: {
    id: 'cert-spotter',
    name: 'Cert Spotter CT',
    url: CERT_SPOTTER_BASE,
    descriptionKey: 'source.certSpotter',
  },
} satisfies Record<string, EvidenceSource>

function nowIso(): string {
  return new Date().toISOString()
}

function okResult<T>(source: EvidenceSource, data: T, warning?: string): SourceResult<T> {
  return { status: warning ? 'warning' : 'success', data, error: warning, queriedAt: nowIso(), source }
}

function errorResult<T>(source: EvidenceSource, data: T, error: unknown): SourceResult<T> {
  const message = error instanceof Error ? error.message : String(error)
  return { status: 'error', data, error: message, queriedAt: nowIso(), source }
}

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const controller = new AbortController()
  const timeout = window.setTimeout(() => controller.abort(), TIMEOUT_MS)
  try {
    const response = await fetch(url, { ...init, signal: controller.signal })
    if (!response.ok) throw new Error(`HTTP ${response.status} from ${url}`)
    return (await response.json()) as T
  } finally {
    window.clearTimeout(timeout)
  }
}

interface DnsAnswer {
  name?: string
  type?: number
  TTL?: number
  data?: string
}

interface DnsResponse {
  Answer?: DnsAnswer[]
}

const DNS_TYPE_TO_CODE: Record<DnsType, number> = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  CAA: 257,
}

const DNS_CODE_TO_TYPE = Object.fromEntries(
  Object.entries(DNS_TYPE_TO_CODE).map(([type, code]) => [code, type]),
) as Record<number, DnsType>

function stripTrailingDot(value: string): string {
  return value.replace(/\.$/, '')
}

export function parseDnsResponse(type: DnsType, response: DnsResponse): DnsRecord[] {
  return (response.Answer ?? [])
    .filter((answer) => answer.data && answer.type === DNS_TYPE_TO_CODE[type])
    .map((answer) => {
      const value = stripTrailingDot(answer.data ?? '')
      const record: DnsRecord = {
        type: DNS_CODE_TO_TYPE[answer.type ?? DNS_TYPE_TO_CODE[type]] ?? type,
        name: stripTrailingDot(answer.name ?? ''),
        value,
        ttl: answer.TTL,
      }
      if (type === 'MX') {
        const [priority, ...hostParts] = value.split(/\s+/)
        record.priority = Number(priority)
        record.value = stripTrailingDot(hostParts.join(' '))
      }
      return record
    })
}

export async function fetchDnsRecords(domain: string): Promise<SourceResult<DnsRecord[]>> {
  try {
    const batches = await Promise.all(
      DNS_TYPES.map(async (type) => {
        const url = `${CLOUDFLARE_DOH}?name=${encodeURIComponent(domain)}&type=${type}`
        const json = await fetchJson<DnsResponse>(url, { headers: { accept: 'application/dns-json' } })
        return parseDnsResponse(type, json)
      }),
    )
    return okResult(sourceCatalog.dns, batches.flat())
  } catch (error) {
    return errorResult(sourceCatalog.dns, [], error)
  }
}

interface RdapEvent {
  eventAction?: string
  eventDate?: string
}

interface RdapLink {
  href?: string
}

interface RdapNameserver {
  ldhName?: string
}

interface VCardItem extends Array<unknown> {
  0: string
  3?: unknown
}

interface RdapEntityJson {
  handle?: string
  roles?: string[]
  vcardArray?: ['vcard', VCardItem[]]
}

interface RdapDomainJson {
  handle?: string
  ldhName?: string
  status?: string[]
  country?: string
  events?: RdapEvent[]
  nameservers?: RdapNameserver[]
  entities?: RdapEntityJson[]
  links?: RdapLink[]
}

interface RdapIpJson {
  handle?: string
  name?: string
  country?: string
  startAddress?: string
  endAddress?: string
  links?: RdapLink[]
}

function entityName(entity: RdapEntityJson): string | undefined {
  const vcard = entity.vcardArray?.[1]
  const fn = vcard?.find((item) => item[0] === 'fn')
  return typeof fn?.[3] === 'string' ? fn[3] : undefined
}

function summarizeEntity(entity: RdapEntityJson): RdapEntity {
  return { handle: entity.handle, roles: entity.roles ?? [], name: entityName(entity) }
}

export function summarizeRdapDomain(json: RdapDomainJson): RdapSummary {
  const registrar = json.entities?.find((entity) => entity.roles?.includes('registrar'))
  return {
    handle: json.handle,
    name: json.ldhName,
    status: json.status ?? [],
    registrar: registrar ? entityName(registrar) ?? registrar.handle : undefined,
    country: json.country,
    events: (json.events ?? [])
      .filter((event): event is Required<RdapEvent> => Boolean(event.eventAction && event.eventDate))
      .map((event) => ({ action: event.eventAction, date: event.eventDate })),
    nameservers: uniqueSorted((json.nameservers ?? []).map((server) => server.ldhName ?? '')),
    entities: (json.entities ?? []).map(summarizeEntity),
    links: uniqueSorted((json.links ?? []).map((link) => link.href ?? '')),
  }
}

export async function fetchRdapSummary(domain: string): Promise<SourceResult<RdapSummary | null>> {
  try {
    const url = `${RDAP_DOMAIN_BASE}${encodeURIComponent(domain)}`
    const json = await fetchJson<RdapDomainJson>(url)
    return okResult(sourceCatalog.rdap, summarizeRdapDomain(json))
  } catch (error) {
    return errorResult(sourceCatalog.rdap, null, error)
  }
}

function summarizeIpRdap(ip: string, json: RdapIpJson): IpRdapSummary {
  return {
    ip,
    handle: json.handle,
    name: json.name,
    country: json.country,
    startAddress: json.startAddress,
    endAddress: json.endAddress,
    links: uniqueSorted((json.links ?? []).map((link) => link.href ?? '')),
  }
}

export async function fetchIpRdapSummaries(records: DnsRecord[]): Promise<SourceResult<IpRdapSummary[]>> {
  const ips = uniqueSorted(records.filter((record) => record.type === 'A' || record.type === 'AAAA').map((record) => record.value))
  if (ips.length === 0) return okResult(sourceCatalog.ipRdap, [])

  try {
    const settled = await Promise.allSettled(
      ips.slice(0, 12).map(async (ip) => {
        const url = `${RDAP_IP_BASE}${ip}`
        return summarizeIpRdap(ip, await fetchJson<RdapIpJson>(url))
      }),
    )
    const summaries = settled
      .filter((item): item is PromiseFulfilledResult<IpRdapSummary> => item.status === 'fulfilled')
      .map((item) => item.value)
    const failures = settled.length - summaries.length
    return okResult(sourceCatalog.ipRdap, summaries, failures ? `${failures} IP RDAP lookup(s) failed.` : undefined)
  } catch (error) {
    return errorResult(sourceCatalog.ipRdap, [], error)
  }
}

interface CertSpotterIssuer {
  name?: string
}

interface CertSpotterIssuance {
  id?: string
  dns_names?: string[]
  issuer?: CertSpotterIssuer
  not_before?: string
  not_after?: string
  cert_der_sha256?: string
}

export function parseCertificateSummaries(json: CertSpotterIssuance[], domain: string): CertificateSummary[] {
  return json.map((item, index) => ({
    id: item.id ?? `${domain}-${index}`,
    dnsNames: uniqueSorted(item.dns_names ?? []),
    issuer: item.issuer?.name,
    notBefore: item.not_before,
    notAfter: item.not_after,
    certDerSha256: item.cert_der_sha256,
    sourceUrl: `${CERT_SPOTTER_BASE}?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names&expand=issuer`,
  }))
}

export async function fetchCertificates(domain: string): Promise<SourceResult<CertificateSummary[]>> {
  try {
    const url = `${CERT_SPOTTER_BASE}?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names&expand=issuer`
    const json = await fetchJson<CertSpotterIssuance[]>(url)
    return okResult(
      sourceCatalog.certs,
      parseCertificateSummaries(json, domain),
      'Cert Spotter is unauthenticated and rate-limited. Results can be partial.',
    )
  } catch (error) {
    return errorResult(sourceCatalog.certs, [], error)
  }
}

function guessedOrg(domain: string): string {
  return domain.split('.')[0]?.replace(/[^a-z0-9-]/g, '') || domain
}

function githubSearchUrl(query: string): string {
  return `https://github.com/search?q=${encodeURIComponent(query)}&type=code`
}

export function buildGithubQueries(domain: string): GithubQuery[] {
  const org = guessedOrg(domain)
  const queries = [
    ['github.quotedDomain', `"${domain}"`],
    ['github.envDomain', `filename:.env "${domain}"`],
    ['github.apiKey', `"${domain}" "api_key"`],
    ['github.token', `"${domain}" "token"`],
    ['github.orgDomain', `org:${org} "${domain}"`],
    ['github.siteSearch', `site:github.com "${domain}"`],
  ] as const
  return queries.map(([labelKey, query], index) => ({
    id: `github-${index}`,
    labelKey,
    query,
    url: githubSearchUrl(query),
  }))
}

export function extractSubdomains(domain: string, certificates: CertificateSummary[]): string[] {
  return uniqueSorted(
    certificates.flatMap((cert) => cert.dnsNames).map((name) => name.replace(/^\*\./, '')).filter((name) => name === domain || name.endsWith(`.${domain}`)),
  )
}

export async function buildDomainReport(domain: string): Promise<DomainReport> {
  const [dns, rdap, certificates] = await Promise.all([
    fetchDnsRecords(domain),
    fetchRdapSummary(domain),
    fetchCertificates(domain),
  ])
  const ipRdap = await fetchIpRdapSummaries(dns.data)
  const warnings = [dns.error, rdap.error, certificates.error, ipRdap.error].filter(Boolean) as string[]
  return {
    domain,
    generatedAt: nowIso(),
    sources: Object.values(sourceCatalog),
    dns,
    rdap,
    ipRdap,
    certificates,
    subdomains: extractSubdomains(domain, certificates.data),
    githubQueries: buildGithubQueries(domain),
    warnings,
  }
}

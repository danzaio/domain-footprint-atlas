import type { CertificateSummary, DomainReport, DnsRecord, IpRdapSummary, RdapSummary } from './atlas'
import type { I18nKey, Locale } from './i18n'
import { translate } from './i18n'

export function reportToJson(report: DomainReport): string {
  return JSON.stringify(report, null, 2)
}

function line(label: string, value: string | number | undefined): string {
  return value ? `- ${label}: ${value}` : ''
}

function joinLines(lines: string[]): string {
  return lines.filter(Boolean).join('\n')
}

function dnsSection(records: DnsRecord[]): string {
  if (records.length === 0) return '- No DNS records returned.'
  return records.map((record) => `- ${record.type} ${record.name} ${record.priority ? `${record.priority} ` : ''}${record.value}`).join('\n')
}

function rdapSection(rdap: RdapSummary | null, t: (key: I18nKey) => string): string {
  if (!rdap) return '- No domain RDAP data returned.'
  return joinLines([
    line(t('field.handle'), rdap.handle),
    line(t('field.status'), rdap.status.join(', ')),
    line(t('field.registrar'), rdap.registrar),
    line(t('field.country'), rdap.country),
    line(t('field.nameservers'), rdap.nameservers.join(', ')),
  ])
}

function ipRdapSection(items: IpRdapSummary[], t: (key: I18nKey) => string): string {
  if (items.length === 0) return '- No IP RDAP data returned.'
  return items
    .map((item) =>
      joinLines([
        `- ${item.ip}`,
        `  - ${t('field.handle')}: ${item.handle ?? 'n/a'}`,
        `  - ${t('field.range')}: ${item.startAddress ?? 'n/a'} - ${item.endAddress ?? 'n/a'}`,
        `  - ${t('field.country')}: ${item.country ?? 'n/a'}`,
      ]),
    )
    .join('\n')
}

function certificateSection(certificates: CertificateSummary[], t: (key: I18nKey) => string): string {
  if (certificates.length === 0) return '- No certificate rows returned.'
  return certificates
    .slice(0, 25)
    .map((cert) =>
      joinLines([
        `- ${cert.dnsNames.slice(0, 6).join(', ') || cert.id}`,
        `  - ${t('field.issuer')}: ${cert.issuer ?? 'n/a'}`,
        `  - ${t('field.validity')}: ${cert.notBefore ?? 'n/a'} - ${cert.notAfter ?? 'n/a'}`,
        `  - SHA256: ${cert.certDerSha256 ?? 'n/a'}`,
      ]),
    )
    .join('\n')
}

export function reportToMarkdown(report: DomainReport, locale: Locale): string {
  const t = (key: I18nKey) => translate(locale, key)
  return joinLines([
    `# ${t('export.heading')}: ${report.domain}`,
    '',
    `- ${t('field.timestamp')}: ${report.generatedAt}`,
    `- ${t('app.disclaimer')}`,
    `- ${t('certs.warning')}`,
    '',
    `## ${t('overview.title')}`,
    `- ${t('overview.records')}: ${report.dns.data.length}`,
    `- ${t('overview.subdomains')}: ${report.subdomains.length}`,
    `- ${t('overview.certificates')}: ${report.certificates.data.length}`,
    `- ${t('overview.githubQueries')}: ${report.githubQueries.length}`,
    '',
    `## ${t('dns.title')}`,
    dnsSection(report.dns.data),
    '',
    `## ${t('rdap.domain')}`,
    rdapSection(report.rdap.data, t),
    '',
    `## ${t('rdap.network')}`,
    ipRdapSection(report.ipRdap.data, t),
    '',
    `## ${t('certs.title')}`,
    certificateSection(report.certificates.data, t),
    '',
    `## ${t('github.title')}`,
    report.githubQueries.map((query) => `- ${t(query.labelKey as I18nKey)}: \`${query.query}\`\n  - ${query.url}`).join('\n'),
    '',
    `## ${t('overview.sources')}`,
    report.sources.map((source) => `- ${source.name}: ${source.url}`).join('\n'),
    '',
    `## ${t('overview.warnings')}`,
    report.warnings.length ? report.warnings.map((warning) => `- ${warning}`).join('\n') : '- None.',
  ])
}

export function downloadText(filename: string, text: string, type: string): void {
  const blob = new Blob([text], { type })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.append(anchor)
  anchor.click()
  anchor.remove()
  URL.revokeObjectURL(url)
}

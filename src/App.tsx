import { useEffect, useMemo, useState } from 'react'
import './App.css'
import type { FormEvent } from 'react'
import type { DomainReport, SourceResult, SourceStatus } from './lib/atlas'
import { normalizeDomain } from './lib/atlas'
import { downloadText, reportToJson, reportToMarkdown } from './lib/exporters'
import { buildDomainReport } from './lib/sources'
import type { I18nKey, Locale } from './lib/i18n'
import { detectLocale, translate } from './lib/i18n'

type SectionId = 'overview' | 'dns' | 'rdap' | 'certificates' | 'github' | 'timeline' | 'export'

const sections: Array<{ id: SectionId; label: I18nKey }> = [
  { id: 'overview', label: 'nav.overview' },
  { id: 'dns', label: 'nav.dns' },
  { id: 'rdap', label: 'nav.rdap' },
  { id: 'certificates', label: 'nav.certificates' },
  { id: 'github', label: 'nav.github' },
  { id: 'timeline', label: 'nav.timeline' },
  { id: 'export', label: 'nav.export' },
]

const localeStorageKey = 'domain-footprint-atlas-locale'

function initialLocale(): Locale {
  const stored = window.localStorage.getItem(localeStorageKey)
  return stored === 'pt-BR' || stored === 'en-US' ? stored : detectLocale(window.navigator.language)
}

function statusLabel(status: SourceStatus, t: (key: I18nKey) => string): string {
  return t(`panel.status.${status}` as I18nKey)
}

function StatusBadge({ status, t }: { status: SourceStatus; t: (key: I18nKey) => string }) {
  return <span className={`status status-${status}`}>{statusLabel(status, t)}</span>
}

function SourceNote<T>({ result, t }: { result: SourceResult<T>; t: (key: I18nKey) => string }) {
  return (
    <div className="source-note">
      <StatusBadge status={result.status} t={t} />
      <span>{result.source.name}</span>
      <span>{t(result.source.descriptionKey as I18nKey)}</span>
      {result.error ? <strong>{result.error}</strong> : null}
    </div>
  )
}

function Metric({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  )
}

function EmptyPanel({ title, body }: { title: string; body: string }) {
  return (
    <div className="empty-panel">
      <h2>{title}</h2>
      <p>{body}</p>
    </div>
  )
}

function Overview({ report, t }: { report: DomainReport | null; t: (key: I18nKey) => string }) {
  if (!report) return <EmptyPanel title={t('app.emptyTitle')} body={t('app.emptyBody')} />

  return (
    <section className="panel" id="overview">
      <div className="section-title">
        <h2>{t('overview.title')}</h2>
        <p>{report.domain}</p>
      </div>
      <div className="metrics-grid">
        <Metric label={t('overview.records')} value={report.dns.data.length} />
        <Metric label={t('overview.subdomains')} value={report.subdomains.length} />
        <Metric label={t('overview.certificates')} value={report.certificates.data.length} />
        <Metric label={t('overview.githubQueries')} value={report.githubQueries.length} />
      </div>
      <div className="source-grid">
        <SourceNote result={report.dns} t={t} />
        <SourceNote result={report.rdap} t={t} />
        <SourceNote result={report.ipRdap} t={t} />
        <SourceNote result={report.certificates} t={t} />
      </div>
      {report.warnings.length ? (
        <div className="warning-box">
          <h3>{t('overview.warnings')}</h3>
          <ul>
            {report.warnings.map((warning) => (
              <li key={warning}>{warning}</li>
            ))}
          </ul>
        </div>
      ) : null}
    </section>
  )
}

function DnsPanel({ report, t }: { report: DomainReport | null; t: (key: I18nKey) => string }) {
  return (
    <section className="panel" id="dns">
      <div className="section-title">
        <h2>{t('dns.title')}</h2>
        {report ? <SourceNote result={report.dns} t={t} /> : null}
      </div>
      {report && report.dns.data.length ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Type</th>
                <th>Name</th>
                <th>Value</th>
                <th>TTL</th>
              </tr>
            </thead>
            <tbody>
              {report.dns.data.map((record, index) => (
                <tr key={`${record.type}-${record.value}-${index}`}>
                  <td>{record.type}</td>
                  <td>{record.name}</td>
                  <td>{record.priority ? `${record.priority} ${record.value}` : record.value}</td>
                  <td>{record.ttl ?? 'n/a'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="muted">{t('dns.empty')}</p>
      )}
    </section>
  )
}

function RdapPanel({ report, t }: { report: DomainReport | null; t: (key: I18nKey) => string }) {
  const rdap = report?.rdap.data
  return (
    <section className="panel" id="rdap">
      <div className="section-title">
        <h2>{t('rdap.title')}</h2>
      </div>
      <div className="split-grid">
        <div className="subpanel">
          <h3>{t('rdap.domain')}</h3>
          {report ? <SourceNote result={report.rdap} t={t} /> : null}
          {rdap ? (
            <dl className="definition-list">
              <dt>{t('field.handle')}</dt>
              <dd>{rdap.handle ?? 'n/a'}</dd>
              <dt>{t('field.status')}</dt>
              <dd>{rdap.status.join(', ') || 'n/a'}</dd>
              <dt>{t('field.registrar')}</dt>
              <dd>{rdap.registrar ?? 'n/a'}</dd>
              <dt>{t('field.country')}</dt>
              <dd>{rdap.country ?? 'n/a'}</dd>
              <dt>{t('field.nameservers')}</dt>
              <dd>{rdap.nameservers.join(', ') || 'n/a'}</dd>
            </dl>
          ) : (
            <p className="muted">{t('rdap.empty')}</p>
          )}
        </div>
        <div className="subpanel">
          <h3>{t('rdap.network')}</h3>
          {report ? <SourceNote result={report.ipRdap} t={t} /> : null}
          {report?.ipRdap.data.length ? (
            <div className="stack-list">
              {report.ipRdap.data.map((item) => (
                <article key={item.ip}>
                  <strong>{item.ip}</strong>
                  <span>{item.name ?? item.handle ?? 'n/a'}</span>
                  <span>{item.startAddress ?? 'n/a'} - {item.endAddress ?? 'n/a'}</span>
                </article>
              ))}
            </div>
          ) : (
            <p className="muted">{t('rdap.empty')}</p>
          )}
        </div>
      </div>
    </section>
  )
}

function CertificatesPanel({ report, t }: { report: DomainReport | null; t: (key: I18nKey) => string }) {
  return (
    <section className="panel" id="certificates">
      <div className="section-title">
        <h2>{t('certs.title')}</h2>
        <p>{t('certs.warning')}</p>
        {report ? <SourceNote result={report.certificates} t={t} /> : null}
      </div>
      {report?.certificates.data.length ? (
        <div className="card-grid">
          {report.certificates.data.slice(0, 18).map((cert) => (
            <article className="cert-card" key={cert.id}>
              <h3>{cert.dnsNames.slice(0, 3).join(', ') || cert.id}</h3>
              <dl>
                <dt>{t('field.issuer')}</dt>
                <dd>{cert.issuer ?? 'n/a'}</dd>
                <dt>{t('field.validity')}</dt>
                <dd>{cert.notBefore ?? 'n/a'} - {cert.notAfter ?? 'n/a'}</dd>
              </dl>
            </article>
          ))}
        </div>
      ) : (
        <p className="muted">{t('certs.empty')}</p>
      )}
    </section>
  )
}

function GithubPanel({ report, t }: { report: DomainReport | null; t: (key: I18nKey) => string }) {
  return (
    <section className="panel" id="github">
      <div className="section-title">
        <h2>{t('github.title')}</h2>
        <p>{t('github.body')}</p>
      </div>
      {report ? (
        <div className="query-list">
          {report.githubQueries.map((query) => (
            <a href={query.url} target="_blank" rel="noreferrer" key={query.id}>
              <span>{t(query.labelKey as I18nKey)}</span>
              <code>{query.query}</code>
            </a>
          ))}
          <a href={`https://crt.sh/?q=${encodeURIComponent(`%.${report.domain}`)}`} target="_blank" rel="noreferrer">
            <span>{t('link.crtsh')}</span>
            <code>crt.sh %.{report.domain}</code>
          </a>
        </div>
      ) : (
        <p className="muted">{t('app.emptyBody')}</p>
      )}
    </section>
  )
}

function TimelinePanel({ report, t }: { report: DomainReport | null; t: (key: I18nKey) => string }) {
  const events = useMemo(() => {
    if (!report) return []
    const rdapEvents = (report.rdap.data?.events ?? []).map((event) => ({ date: event.date, label: event.action }))
    const certEvents = report.certificates.data.flatMap((cert) => [
      cert.notBefore ? { date: cert.notBefore, label: `${cert.dnsNames[0] ?? cert.id} valid from` } : null,
      cert.notAfter ? { date: cert.notAfter, label: `${cert.dnsNames[0] ?? cert.id} expires` } : null,
    ])
    return [...rdapEvents, ...certEvents.filter((event): event is { date: string; label: string } => Boolean(event))]
      .sort((a, b) => a.date.localeCompare(b.date))
      .slice(0, 40)
  }, [report])

  return (
    <section className="panel" id="timeline">
      <div className="section-title">
        <h2>{t('timeline.title')}</h2>
      </div>
      {events.length ? (
        <ol className="timeline">
          {events.map((event, index) => (
            <li key={`${event.date}-${event.label}-${index}`}>
              <time>{event.date}</time>
              <span>{event.label}</span>
            </li>
          ))}
        </ol>
      ) : (
        <p className="muted">{t('timeline.empty')}</p>
      )}
    </section>
  )
}

function ExportPanel({ report, locale, t }: { report: DomainReport | null; locale: Locale; t: (key: I18nKey) => string }) {
  const [notice, setNotice] = useState('')
  const json = report ? reportToJson(report) : ''
  const markdown = report ? reportToMarkdown(report, locale) : ''

  async function copy(text: string): Promise<void> {
    await navigator.clipboard.writeText(text)
    setNotice(t('export.copied'))
  }

  return (
    <section className="panel" id="export">
      <div className="section-title">
        <h2>{t('export.title')}</h2>
        <p>{t('app.disclaimer')}</p>
      </div>
      <div className="export-actions">
        <button type="button" disabled={!report} onClick={() => copy(json)}>{t('export.copyJson')}</button>
        <button type="button" disabled={!report} onClick={() => report && downloadText(`${report.domain}-atlas.json`, json, 'application/json')}>{t('export.downloadJson')}</button>
        <button type="button" disabled={!report} onClick={() => copy(markdown)}>{t('export.copyMarkdown')}</button>
        <button type="button" disabled={!report} onClick={() => report && downloadText(`${report.domain}-atlas.md`, markdown, 'text/markdown')}>{t('export.downloadMarkdown')}</button>
      </div>
      {notice ? <p className="notice">{notice}</p> : null}
      {report ? <pre className="markdown-preview">{markdown}</pre> : <p className="muted">{t('app.emptyBody')}</p>}
    </section>
  )
}

function App() {
  const [locale, setLocale] = useState<Locale>(initialLocale)
  const [domainInput, setDomainInput] = useState('')
  const [report, setReport] = useState<DomainReport | null>(null)
  const [errorKey, setErrorKey] = useState<I18nKey | null>(null)
  const [loading, setLoading] = useState(false)
  const t = (key: I18nKey) => translate(locale, key)

  useEffect(() => {
    window.localStorage.setItem(localeStorageKey, locale)
    document.documentElement.lang = locale
  }, [locale])

  async function onSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    const normalized = normalizeDomain(domainInput)
    if (!normalized.ok) {
      setErrorKey(`validation.${normalized.errorKey}` as I18nKey)
      return
    }
    setErrorKey(null)
    setLoading(true)
    try {
      const nextReport = await buildDomainReport(normalized.domain)
      setDomainInput(normalized.domain)
      setReport(nextReport)
    } finally {
      setLoading(false)
    }
  }

  return (
    <main>
      <header className="topbar">
        <a className="brand" href="#top">{t('app.title')}</a>
        <nav aria-label="Primary">
          {sections.map((section) => (
            <a href={`#${section.id}`} key={section.id}>{t(section.label)}</a>
          ))}
        </nav>
        <label className="locale-toggle">
          <span>{t('app.locale')}</span>
          <select value={locale} onChange={(event) => setLocale(event.target.value as Locale)}>
            <option value="pt-BR">PT-BR</option>
            <option value="en-US">EN-US</option>
          </select>
        </label>
      </header>

      <section className="hero" id="top">
        <div className="hero-copy">
          <span className="eyebrow">Passive OSINT</span>
          <h1>{t('app.title')}</h1>
          <p>{t('app.subtitle')}</p>
          <form onSubmit={onSubmit} noValidate>
            <label htmlFor="domain-input">{t('app.domainLabel')}</label>
            <div className="input-row">
              <input
                id="domain-input"
                value={domainInput}
                onChange={(event) => setDomainInput(event.target.value)}
                placeholder={t('app.placeholder')}
                aria-describedby="domain-help domain-error"
              />
              <button type="submit" disabled={loading}>{loading ? t('app.running') : t('app.run')}</button>
              <button type="button" className="secondary" onClick={() => { setReport(null); setErrorKey(null); setDomainInput('') }}>{t('app.reset')}</button>
            </div>
            <p id="domain-help" className="helper">{t('app.domainHelp')}</p>
            {errorKey ? <p id="domain-error" className="error-text">{t(errorKey)}</p> : null}
          </form>
        </div>
        <aside className="hero-aside" aria-label={t('overview.sources')}>
          <div>
            <strong>{t('app.disclaimer')}</strong>
            <span>{report ? `${t('app.generated')}: ${report.generatedAt}` : t('app.emptyBody')}</span>
          </div>
          <div className="mini-menu">
            {sections.map((section) => (
              <a href={`#${section.id}`} key={section.id}>{t(section.label)}</a>
            ))}
          </div>
        </aside>
      </section>

      <div className="layout">
        <aside className="side-menu" aria-label="Section menu">
          {sections.map((section) => (
            <a href={`#${section.id}`} key={section.id}>{t(section.label)}</a>
          ))}
        </aside>
        <div className="content-stack">
          <Overview report={report} t={t} />
          <DnsPanel report={report} t={t} />
          <RdapPanel report={report} t={t} />
          <CertificatesPanel report={report} t={t} />
          <GithubPanel report={report} t={t} />
          <TimelinePanel report={report} t={t} />
          <ExportPanel report={report} locale={locale} t={t} />
        </div>
      </div>
    </main>
  )
}

export default App

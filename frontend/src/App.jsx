
import { useState } from 'react'
import './App.css'

const API_URL = 'http://127.0.0.1:8000'

function StatusBadge({ status }) {
  const value = (status || 'unknown').toLowerCase()

  const labels = {
    pass: 'Passed',
    success: 'Passed',
    valid: 'Valid',
    warning: 'Warning',
    partial: 'Partial',
    fail: 'Failed',
    error: 'Error',
    invalid: 'Invalid',
    not_checked: 'Not checked',
    not_found: 'Not found',
    unverifiable: 'Unverifiable',
    revoked: 'Revoked',
  }

  return (
    <span className={`status-badge ${value}`}>
      <span className="status-dot" />
      {labels[value] || value.replaceAll('_', ' ')}
    </span>
  )
}


function CopyButton({ value }) {
  const [copied, setCopied] = useState(false)

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      setCopied(false)
    }
  }

  return (
    <button
      type="button"
      className="copy-button"
      onClick={handleCopy}
      disabled={!value}
      title={copied ? 'Copied!' : 'Copy record'}
aria-label={copied ? 'Copied' : 'Copy record'}
    >
      {copied ? (
  <span aria-label="Copied">✓</span>
) : (
  <svg
    width="15"
    height="15"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.8"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
  >
    <rect x="8" y="8" width="13" height="13" rx="2" />
    <path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3" />
  </svg>
)}


    </button>
  )
}


function DetailRow({ label, value }) {
  if (value === undefined || value === null || value === '') return null

  return (
    <div className="detail-row">
      <span>{label}</span>
      <strong>{String(value)}</strong>
    </div>
  )
}

function ProtocolCard({ type, name, description, status, summary, record }) {
  const dkimNotChecked = type === 'dkim' && status === 'not_checked'

  return (
    <article className={`protocol-card ${type}`}>
      <div className="protocol-top">
        <span className={`protocol-mark ${type}`}>
          {type.toUpperCase()}
        </span>
        <StatusBadge status={status} />
      </div>

      <h3>{name}</h3>
      <p className="protocol-description">{description}</p>

      <div className="protocol-summary">
        {dkimNotChecked ? 'Not checked' : summary}
      </div>

      {dkimNotChecked && (
        <div className="dkim-help">
          <p>
            No DKIM selector was provided. MailGuard couldn't locate
            the DKIM public key without a selector.
          </p>

          <strong>How to find your selector</strong>

          <ol>
            <li>Send yourself an email from your domain.</li>
            <li>
              Open that email's original headers or select
              "Show original".
            </li>
            <li>
              Find the <code>DKIM-Signature</code> header.
            </li>
            <li>
              Look for <code>s=</code>, for example <code>s=nc2048</code>.
            </li>
          </ol>

          <div className="dkim-example">
            <strong>Example</strong>
            <p>
              If the header contains <code>s=nc2048</code>, enter
              <code> nc2048 </code> as your selector.
            </p>
          </div>
        </div>
      )}

      {record && (
        <details className="technical-details">
          <summary>View DNS record</summary>
          <pre>{record}</pre>
        </details>
      )}
    </article>
  )
}



function FindingCard({ finding, index }) {
  const findingTitles = {
    dkim_not_found: 'DKIM selector not found',
    dkim_not_checked: 'DKIM was not checked',
    dkim_unverifiable: 'DKIM lookup could not be completed',
    dkim_invalid_input: 'Invalid DKIM selector',
    dkim_invalid: 'DKIM record is invalid',
    dkim_revoked: 'DKIM key has been revoked',
  }

  const title =
    findingTitles[finding.code] ||
    `${finding.check?.toUpperCase() || 'GENERAL'} finding`

  return (
    <article className="finding" key={`${finding.code}-${index}`}>
      <div className="finding-number">
        {String(index + 1).padStart(2, '0')}
      </div>

      <div className="finding-content">
        <div className="finding-top">
          <strong>{title}</strong>
          <StatusBadge status={finding.severity} />
        </div>

        <div className="finding-section">
          <span className="finding-label">WHAT WE FOUND</span>
          <p>{finding.message}</p>
          <small className="finding-code">
            {finding.selector ? `SELECTOR: ${finding.selector} · ` : ''}
            {finding.code}
          </small>
        </div>

        {finding.why_it_matters && (
          <div className="finding-section">
            <span className="finding-label">WHY THIS MATTERS</span>
            <p>{finding.why_it_matters}</p>
          </div>
        )}

        {finding.recommendation && (
          <div className="recommendation">
            <strong>RECOMMENDED ACTION</strong>
            <p>{finding.recommendation}</p>
          </div>
        )}

        {finding.dns_example && (
          <div className="dns-example">
            <span className="finding-label">DNS EXAMPLE</span>
            <p>{finding.dns_example.label}</p>

            <div className="dns-example-record">
              <strong>Current record</strong>
              <pre>{finding.dns_example.current_record}</pre>
              <CopyButton value={finding.dns_example.current_record} />
            </div>

            <div className="dns-example-record">
              <strong>Optional alternative to review</strong>
              <pre>{finding.dns_example.alternative_record}</pre>
              <CopyButton value={finding.dns_example.alternative_record} />
            </div>

            <p className="dns-example-note">{finding.dns_example.note}</p>
          </div>
        )}

                {(finding.caution || finding.verification) && (
          <div className="finding-guidance">
            {finding.caution && (
              <div className="finding-caution">
                <strong>CAUTION</strong>
                <p>{finding.caution}</p>
              </div>
            )}

            {finding.verification && (
              <div className="finding-verification">
                <strong>VERIFY</strong>
                <p>{finding.verification}</p>
              </div>
            )}
          </div>
        )}
      </div>
    </article>
  )
}

function App() {
  const [domain, setDomain] = useState('')
  const [selectors, setSelectors] = useState('')
  const [audit, setAudit] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [activeFindingTab, setActiveFindingTab] = useState('')

  async function runAudit(event) {
    event.preventDefault()
    setError('')

    const cleanDomain = domain.trim()

    if (!cleanDomain) {
      setError('Please enter a domain name.')
      return
    }

    const selectorList = selectors
      .split(',')
      .map((item) => item.trim())
      .filter(Boolean)

    setLoading(true)

    try {
      const response = await fetch(`${API_URL}/api/audits`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({
          domain: cleanDomain,
          selectors: selectorList,
        }),
      })

      const data = await response.json()

      if (!response.ok) {
        const detail = data.detail
        throw new Error(
          Array.isArray(detail)
            ? detail.map((item) => item.msg).join(', ')
            : typeof detail === 'string'
              ? detail
              : 'The audit request failed.',
        )
      }

      setAudit(data)
    } catch (err) {
      setError(
        err.message === 'Failed to fetch'
          ? 'Could not connect to the backend. Check that FastAPI is running on port 8000 and CORS is configured.'
          : err.message,
      )
    } finally {
      setLoading(false)
    }
  }

  const checks = audit?.checks || {}
  const findings = audit?.findings || []

  const actionableFindings = findings.filter(
  (finding) => finding.severity !== 'info'
)

const informationalFindings = findings.filter(
  (finding) => finding.severity === 'info'
)

const criticalFindings = findings.filter(
  (finding) => ['critical', 'fail'].includes(finding.severity)
)

const warningFindings = findings.filter(
  (finding) =>
    finding.severity !== 'info' &&
    !['critical', 'fail'].includes(finding.severity)
)

const findingTabs = [
  { id: 'info', label: 'Informational notes', items: informationalFindings },
  { id: 'warning', label: 'Warnings', items: warningFindings },
  { id: 'critical', label: 'Critical', items: criticalFindings },
]

const defaultFindingTab =
  findingTabs.find((tab) => tab.items.length > 0) || findingTabs[0]

const selectedFindingTab =
  findingTabs.find((tab) => tab.id === activeFindingTab) ||
  defaultFindingTab

const visibleFindings = selectedFindingTab.items

  const spf = checks.spf || {}
  const spfConfig = spf.configuration || {}
  const dkim = checks.dkim || {}
  const dmarc = checks.dmarc || {}

  const spfStatus = spfConfig.status || spf.status
  const spfRecord = spfConfig.record
  const dmarcRecord = dmarc.record

  const protocols = [
    {
      type: 'spf',
      name: 'Sender Policy Framework',
      description: 'Controls which mail servers are authorised to send email for this domain.',
      status: spfStatus,
      summary: spfRecord || 'No SPF record information was returned.',
      record: spfRecord,
    },
    {
      type: 'dkim',
      name: 'DomainKeys Identified Mail',
      description: 'Uses a cryptographic public key stored in DNS to help verify email authenticity and detect message tampering.',
      status: dkim.status,
      summary: dkim.selectors_checked?.length
        ? `${dkim.selectors_checked.length} selector(s) checked`
        : 'No selector supplied. DKIM has not been checked.',
      record: null,
    },
    {
      type: 'dmarc',
      name: 'Domain-based Message Authentication',
      description: 'Tells receiving mail servers how to handle messages that fail authentication.',
      status: dmarc.status,
      summary: dmarcRecord || 'No DMARC record information was returned.',
      record: dmarcRecord,
    },
  ]

const protocolStatuses = [
  spfStatus,
  dkim.status,
  dmarc.status,
]

const assessedCount = protocolStatuses.filter(
  (status) => status && status !== 'not_checked'
).length

const passedCount = protocolStatuses.filter(
  (status) => ['pass', 'success', 'valid'].includes(status)
).length

const needsReviewCount = assessedCount - passedCount

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">M</div>
          <div>
            <div className="brand-name">MailGuard</div>
            <div className="brand-caption">Email authentication</div>
          </div>
        </div>

        <div className="workspace-box">
          <span>WORKSPACE</span>
          <strong>Agency workspace</strong>
        </div>

        <div className="sidebar-label">WORKSPACE</div>

        <nav className="nav-links">
          <a className="nav-link active" href="#audit">
            <span className="nav-symbol">◎</span>
            Domain audit
          </a>
          <div className="nav-link disabled">
            <span className="nav-symbol">↻</span>
            Audit history
            <span className="coming-soon">Soon</span>
          </div>
          <div className="nav-link disabled">
            <span className="nav-symbol">⚙</span>
            Settings
            <span className="coming-soon">Soon</span>
          </div>
        </nav>

        <div className="sidebar-bottom">
          <div className="sidebar-note">
            <span className="note-symbol">i</span>
            <div>
              <strong>About MailGuard</strong>
              <p>Understand and improve your domain's email authentication.</p>
            </div>
          </div>
          <div className="sidebar-footer">MAILGUARD · MVP</div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumb">
            Workspace <span>/</span> <strong>Domain audit</strong>
          </div>
          <div className="topbar-right">
            <span className="environment-label">Development workspace</span>
            <span className="topbar-avatar">MG</span>
          </div>
        </header>

        <div className="page-content" id="audit">
          <section className="page-heading">
            <div>
              <div className="eyebrow">AUDITING ENGINE / DOMAIN SECURITY</div>
              <h1>Email authentication overview</h1>
              <p>
                Inspect your domain's email security configuration and
                understand what needs attention.
              </p>
            </div>
            <div className="heading-tag">DNS AUDIT</div>
          </section>

          <section className="audit-form-card">
            <div className="form-heading">
              <div>
                <span className="section-kicker">NEW INSPECTION</span>
                <h2>Run a domain audit</h2>
                <p>Enter a domain to inspect its SPF, DKIM and DMARC records.</p>
              </div>
              <div className="form-mark">01</div>
            </div>

            <form onSubmit={runAudit}>
              <div className="form-fields">
                <label className="field domain-field">
                  <span>Target domain <b>*</b></span>
                  <input
                    type="text"
                    placeholder="example.com"
                    value={domain}
                    onChange={(e) => setDomain(e.target.value)}
                    required
                  />
                </label>

                <label className="field selector-field">
                  <span>
                    DKIM selector <small>OPTIONAL</small>
                  </span>
                  <input
                    type="text"
                    placeholder="google, selector1"
                    value={selectors}
                    onChange={(e) => setSelectors(e.target.value)}
                  />
                </label>

                <button className="audit-button" type="submit" disabled={loading}>
                  {loading ? 'Checking...' : 'Run audit'}
                  <span aria-hidden="true">→</span>
                </button>
              </div>

              <div className="form-bottom">
                <p>
                  Multiple selectors can be separated by commas. Leave blank
                  if you don't know your DKIM selector.
                </p>
                <span>DNS RECORD INSPECTION</span>
              </div>
            </form>

            {error && <div className="error-message">{error}</div>}
          </section>

          {!audit && !loading && (
            <section className="empty-state">
              <div className="empty-symbol">◎</div>
              <div>
                <span className="section-kicker">READY WHEN YOU ARE</span>
                <h2>Your domain report will appear here</h2>
                <p>
                  Run an audit to see your authentication status, DNS records
                  and recommended actions.
                </p>
              </div>
            </section>
          )}

          {loading && (
            <section className="loading-state">
              <div className="loader" />
              <strong>Inspecting your domain</strong>
              <p>Retrieving DNS records and analysing authentication settings.</p>
            </section>
          )}

          {audit && (
            <section className="results-section">
              <div className="audit-overview">
                <div className="overview-domain">
                  <div className="domain-symbol">◎</div>
                  <div>
                    <span className="section-kicker">AUDIT REPORT</span>
                    <h2>{audit.domain}</h2>
                    <p>
                      Root domain: {audit.root_domain || audit.domain}
                    </p>
                  </div>
                </div>
                <div className="overview-status">
                  <span>OVERALL STATUS</span>
                  <StatusBadge status={audit.overall_status} />
                </div>
              </div>

              <div className="results-intro">
                <div>
                  <h2>Authentication checks</h2>
                  <p>
                    {assessedCount} protocols assessed · {passedCount} passed · {needsReviewCount} needs review.
                    below.
                  </p>
                </div>
                <span className="results-count">03 PROTOCOLS</span>
              </div>

              <div className="check-grid">
                {protocols.map((protocol) => (
                  <ProtocolCard key={protocol.type} {...protocol} />
                ))}
              </div>


              {dkim.selectors_checked?.length > 0 && (
                <section className="detail-card">
                  <div className="section-title">
                    <div>
                      <span className="section-kicker">SELECTOR INSPECTION</span>
                      <h3>DKIM selector details</h3>
                      <p>DNS lookup results for the supplied selectors.</p>
                    </div>
                  </div>

                  {dkim.selectors_checked.map((item) => (
                    <div className="selector-result" key={item.selector}>
                      <div className="selector-info">
                        <strong>{item.selector}</strong>
                        <p>{item.record_name || 'Record name unavailable'}</p>

                        <details className="technical-details">
                          <summary>View DNS details</summary>

                          {item.error && (
                            <p className="selector-error">{item.error}</p>
                          )}

                          {item.record && (
                            <>
                              <strong>DNS TXT record</strong>
                              <pre>{item.record}</pre>
                            </>
                          )}

                          {!item.error && !item.record && (
                            <p>DNS lookup status: {item.status}</p>
                          )}
                        </details>
                      </div>

                      <StatusBadge status={item.status} />
                    </div>
                  ))}
                </section>
              )}



                <section className="detail-card findings-card">
                  <div className="section-title">
                    <div>
                      <span className="section-kicker">AUDIT SUMMARY</span>
                      <h3>Findings & recommended actions</h3>
                      <p>
                        Issues identified by the DNS checks and information about
                        anything the audit could not verify.
                      </p>
                    </div>

                    <span className="finding-count">
                      {findings.length} {findings.length === 1 ? 'finding' : 'findings'}
                    </span>
                  </div>

                  {findings.length === 0 ? (
                    <div className="no-findings">
                      <span className="success-symbol">✓</span>
                      <div>
                        <strong>No findings returned</strong>
                        <p>
                          The current validation rules did not identify any
                          findings in the checked records.
                        </p>
                      </div>
                    </div>
                  ) : (
                    <>
                      <div className="finding-tabs" role="group" aria-label="Filter findings">
                        {findingTabs.map((tab) => (
                          <button
                            key={tab.id}
                            type="button"
                            className={`finding-tab ${
                              selectedFindingTab.id === tab.id ? 'active' : ''
                            }`}
                            aria-pressed={selectedFindingTab.id === tab.id}
                            onClick={() => setActiveFindingTab(tab.id)}
                          >
                            <span>{tab.label}</span>
                            <span className="finding-tab-count">{tab.items.length}</span>
                          </button>
                        ))}
                      </div>

                      {visibleFindings.length > 0 ? (
                        <div className="findings-list">
                          {visibleFindings.map((finding, index) => (
                            <FindingCard
                              key={`${finding.code}-${index}`}
                              finding={finding}
                              index={index}
                            />
                          ))}
                        </div>
                      ) : (
                        <div className="no-findings">
                          <strong>No {selectedFindingTab.label.toLowerCase()}.</strong>
                          <p>There are no findings in this category for the current audit.</p>
                        </div>
                      )}
                    </>
                  )}
                </section>


              <div className="audit-meta">
                <span>Audit ID: {audit.audit_id}</span>
                <span>Results generated from DNS validation</span>
              </div>
            </section>
          )}

          <footer className="page-footer">
            <span>MailGuard · Email authentication insights</span>
            <span>Rule-based DNS analysis</span>
          </footer>
        </div>
      </main>
    </div>
  )
}

export default App

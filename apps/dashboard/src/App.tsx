// The Fermata dashboard on Stellar: live calls and escrow events, the per-call proof drawer with
// offline re-verification, reconciliation from events, vendor scores, services, and how to pay.
//
// Ported from Fermata apps/dashboard/src/App.tsx @ d7cc642 (github.com/bilgin-kocak/fermata, MIT).
// Kept: the layout, the tiles, the live tab, the call drawer and its re-verification, the vendor
// scores, the services table, the theme toggle. Changed for Stellar: stellar.expert links, 7-decimal
// amounts, ledgers instead of blocks, the `timed_out` event, how each call was paid (MPP or x402),
// reconciliation as checks over the escrow's events and the token's transfers, and the "Use it"
// snippets. Not ported: the public "try it" panel and onboarding (the gateway does not serve them).
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api, type Call, type EscrowEvent, type Info, type Reconciliation, type Reverify, type Scores, type Service } from './api.ts'
import { STATUS, age, amount, explorerUrl, serviceName, short } from './format.ts'

type Tab = 'live' | 'vendors' | 'use' | 'reconciliation' | 'services'

function usePoll<T>(load: () => Promise<T>, ms: number) {
  const [data, setData] = useState<T>()
  const [error, setError] = useState<string>()
  useEffect(() => {
    let alive = true
    const tick = () =>
      load()
        .then((d) => alive && (setData(d), setError(undefined)))
        .catch((e: Error) => alive && setError(e.message))
    tick()
    const id = setInterval(tick, ms)
    return () => {
      alive = false
      clearInterval(id)
    }
  }, [load, ms])
  return { data, error }
}

/** The fermata sign (𝄐), drawn so it renders without a music font. */
function Fermata() {
  return (
    <svg className="glyph" viewBox="0 0 40 24" width="34" height="21" aria-label="fermata" role="img">
      <path d="M3 21 A17 17 0 0 1 37 21" fill="none" stroke="currentColor" strokeWidth="3.2" strokeLinecap="round" />
      <circle cx="20" cy="17.5" r="3.4" fill="currentColor" />
    </svg>
  )
}

/** A transaction, contract or account: linked to the explorer when there is one. */
function Ref({ value, info, n }: { value?: string | null; info?: Info; n?: number }) {
  if (!value) return <span className="muted">—</span>
  return info?.explorer ? (
    <a className="mono" href={explorerUrl(info.explorer, value)} target="_blank" rel="noreferrer" title={value}>
      {short(value, n)}
    </a>
  ) : (
    <span className="mono" title={value}>
      {short(value, n)}
    </span>
  )
}

function StatusChip({ status }: { status: Call['status'] }) {
  const s = STATUS[status]
  return (
    <span className={`chip ${s.role}`}>
      <span className="mark" aria-hidden>
        {s.icon}
      </span>
      {s.label}
    </span>
  )
}

function ThemeToggle() {
  const [theme, setTheme] = useState(() => document.documentElement.dataset.theme ?? '')
  const system = window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
  const current = theme || system
  const flip = () => {
    const next = current === 'dark' ? 'light' : 'dark'
    document.documentElement.dataset.theme = next
    try {
      localStorage.setItem('fermata-theme', next)
    } catch {
      /* private mode */
    }
    setTheme(next)
  }
  return (
    <button onClick={flip} aria-label="Toggle light and dark mode" title="Toggle light / dark">
      {current === 'dark' ? '☀︎ Light' : '☾ Dark'}
    </button>
  )
}

const paidWith = (c: Call) => `${c.paidWith === 'mpp' ? 'MPP' : 'x402'} · ${c.sponsored ? 'sponsored' : 'direct'}`

function Tiles({ calls, services }: { calls: Call[]; services?: Service[] }) {
  const price = new Map(services?.map((s) => [s.serviceId, BigInt(s.price)]))
  const count = (...st: Call['status'][]) => calls.filter((c) => st.includes(c.status)).length
  const released = calls.filter((c) => c.status === 'released')
  const vendorPaid = released.reduce((sum, c) => sum + (price.get(c.serviceId) ?? 0n), 0n)
  const refundedValue = calls
    .filter((c) => c.status === 'refunded' || c.status === 'timed-out')
    .reduce((sum, c) => sum + (price.get(c.serviceId) ?? 0n), 0n)
  const proved = calls.filter((c) => c.proveMs)
  const meanProve = proved.length ? proved.reduce((s, c) => s + (c.proveMs ?? 0), 0) / proved.length : 0
  const tiles = [
    { label: 'Calls held', value: String(calls.length), sub: `${count('holding', 'held', 'settle-pending')} in flight` },
    { label: 'Released to vendor', value: String(released.length), sub: `${amount(vendorPaid)} (fee incl.)` },
    { label: 'Refunded to agent', value: String(count('refunded', 'timed-out')), sub: amount(refundedValue) },
    { label: 'Awaiting timeout', value: String(count('awaiting-timeout')), sub: 'no proof, no verdict' },
    { label: 'Mean prove time', value: meanProve ? `${(meanProve / 1000).toFixed(2)} s` : '—', sub: 'MPC-TLS per call' },
    { label: 'Paid with', value: `${calls.filter((c) => c.paidWith === 'mpp').length} / ${calls.filter((c) => c.paidWith === 'x402').length}`, sub: 'MPP / x402' },
  ]
  return (
    <div className="tiles">
      {tiles.map((t) => (
        <div className="tile" key={t.label}>
          <div className="label">{t.label}</div>
          <div className="value">{t.value}</div>
          <div className="sub">{t.sub}</div>
        </div>
      ))}
    </div>
  )
}

function LiveTab({ calls, events, services, info, onOpen }: { calls: Call[]; events: EscrowEvent[]; services?: Service[]; info?: Info; onOpen: (c: Call) => void }) {
  const now = Date.now()
  const rows = [...calls].reverse()
  const summary = new Map(services?.map((s) => [s.serviceId, s.summary]))
  return (
    <div className="grid-live">
      <div className="panel">
        <h2>
          Calls <span className="muted">{calls.length}</span>
        </h2>
        {rows.length === 0 ? (
          <div className="empty">
            No paid calls yet. Run <span className="mono">scripts/gateway-cases.sh</span>.
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Status</th>
                <th>Call</th>
                <th className="hide-sm">Service</th>
                <th className="hide-sm">Paid with</th>
                <th className="hide-sm">Prove</th>
                <th className="hide-sm">Settle tx</th>
                <th className="hide-sm">Age</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((c) => (
                <tr key={c.callId} className="clickable" onClick={() => onOpen(c)} tabIndex={0} onKeyDown={(e) => e.key === 'Enter' && onOpen(c)}>
                  <td>
                    <StatusChip status={c.status} />
                  </td>
                  <td className="mono">{short(c.callId)}</td>
                  <td className="hide-sm ink2">{serviceName(c.serviceId, summary.get(c.serviceId))}</td>
                  <td className="hide-sm ink2">{paidWith(c)}</td>
                  <td className="hide-sm num">{c.proveMs ? `${(c.proveMs / 1000).toFixed(2)} s` : '—'}</td>
                  <td className="hide-sm">
                    <Ref value={c.settleTx ?? c.timeoutTx} info={info} />
                  </td>
                  <td className="muted num hide-sm">{age(c.createdAt, now)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <div className="panel">
        <h2>
          Escrow events <span className="muted">indexed from the chain</span>
        </h2>
        {events.length === 0 ? (
          <div className="empty">Waiting for held / released / refunded / timed_out…</div>
        ) : (
          <ul className="feed">
            {[...events].reverse().slice(0, 60).map((e) => (
              <li key={e.id}>
                <span className="ev">{e.name}</span>
                <span className="mono">{short(e.callId)}</span>
                <span className="muted num">ledger {e.ledger}</span>
                <span>
                  {e.name === 'released' ? `${amount(e.amount)} (fee ${amount(e.fee ?? 0)})` : amount(e.amount)} <Ref value={e.txHash} info={info} />
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}

function splitHttp(raw: string) {
  const i = raw.indexOf('\r\n\r\n')
  const head = i < 0 ? raw : raw.slice(0, i)
  const body = i < 0 ? '' : raw.slice(i + 4)
  try {
    return { head, body: JSON.stringify(JSON.parse(body), null, 2) }
  } catch {
    return { head, body }
  }
}

function CallDrawer({ call, info, onClose }: { call: Call; info?: Info; onClose: () => void }) {
  const [re, setRe] = useState<Reverify>()
  const [reError, setReError] = useState<string>()
  const [busy, setBusy] = useState(false)
  const [checkedAt, setCheckedAt] = useState<string>()
  const hasProof = !!call.presentationHash
  const run = useCallback(
    async (showChecks: boolean) => {
      setBusy(true)
      try {
        setRe(await api.reverify(call.callId))
        setReError(undefined)
        if (showChecks) setCheckedAt(new Date().toLocaleTimeString())
      } catch (e) {
        setReError((e as Error).message)
      } finally {
        setBusy(false)
      }
    },
    [call.callId],
  )
  // Re-verify once per opened call, not on every dashboard poll (onClose is a new function each render).
  useEffect(() => {
    if (hasProof) void run(false)
  }, [hasProof, run])
  const closeRef = useRef(onClose)
  closeRef.current = onClose
  useEffect(() => {
    const esc = (e: KeyboardEvent) => e.key === 'Escape' && closeRef.current()
    window.addEventListener('keydown', esc)
    return () => window.removeEventListener('keydown', esc)
  }, [])
  const req = re ? splitHttp(re.transcript.request) : undefined
  const res = re ? splitHttp(re.transcript.response) : undefined
  const v = call.verdict as Record<string, string | number> | undefined
  return (
    <>
      <div className="scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label={`Call ${call.callId}`}>
        <header>
          <h3>Call {short(call.callId)}</h3>
          <StatusChip status={call.status} />
          <button onClick={onClose} aria-label="Close">
            ✕
          </button>
        </header>

        <section>
          <dl className="kv">
            <dt>Call id</dt>
            <dd className="mono">{call.callId}</dd>
            <dt>Service</dt>
            <dd className="mono">{call.serviceId}</dd>
            <dt>Request</dt>
            <dd className="mono">
              {call.method} {call.target}
            </dd>
            <dt>Paid with</dt>
            <dd>{paidWith(call)}</dd>
            <dt>Agent</dt>
            <dd>
              <Ref value={call.agent} info={info} n={8} />
            </dd>
            <dt>Outcome</dt>
            <dd>
              {call.outcome ?? '—'}
              {call.failures?.length ? <span className="ink2"> · {call.failures.join('; ')}</span> : null}
            </dd>
            <dt>Hold</dt>
            <dd>
              <Ref value={call.holdTx} info={info} />
            </dd>
            <dt>{call.timeoutTx ? 'Timeout refund' : 'Settle'}</dt>
            <dd>
              <Ref value={call.settleTx ?? call.timeoutTx} info={info} />
            </dd>
            {call.proveMs ? (
              <>
                <dt>Prove</dt>
                <dd className="num">{(call.proveMs / 1000).toFixed(2)} s</dd>
              </>
            ) : null}
            {call.error ? (
              <>
                <dt>Note</dt>
                <dd className="ink2">{call.error}</dd>
              </>
            ) : null}
          </dl>
        </section>

        {!hasProof ? (
          <section>
            <div className="note">
              No transcript exists for this call (the vendor never answered, or the proof could not bind to the hold), so no verdict was ever signed.
              The only exit is the on-chain timeout: after the settlement window anyone can call <span className="mono">claim_timeout</span>, and the
              money goes back to the agent.
            </div>
          </section>
        ) : (
          <>
            <section>
              <h4>Proof</h4>
              <dl className="kv">
                <dt>Presentation</dt>
                <dd className="mono">{call.presentationHash}</dd>
                <dt>Notary key</dt>
                <dd className="mono">{re?.notaryKey ?? '…'}</dd>
                <dt>TLS session</dt>
                <dd className="num">{re ? new Date(re.sessionTime * 1000).toISOString() : '…'}</dd>
                <dt>Verifier</dt>
                <dd className="mono">{call.signer ?? '—'}</dd>
                <dt>Signature</dt>
                <dd className="mono">{call.signature ?? '—'}</dd>
                {v ? (
                  <>
                    <dt>Verdict</dt>
                    <dd className="mono">
                      outcome {String(v.outcome)} · request_hash {short(String(v.request_hash))} · issued_at {String(v.issued_at)}
                    </dd>
                  </>
                ) : null}
              </dl>
              <div className="row-actions" style={{ marginTop: 12 }}>
                <button className="primary" onClick={() => void run(true)} disabled={busy}>
                  {busy ? 'Re-verifying…' : 'Re-verify offline'}
                </button>
                <a href={api.proofUrl(call.callId)} download={`${call.callId}.tlsn`}>
                  <button>Download proof</button>
                </a>
              </div>
              {reError ? <p className="bad">{reError}</p> : null}
            </section>

            {checkedAt && re ? (
              <section>
                <h4>
                  Re-verification <span className={re.ok ? 'ok' : 'bad'}>{re.ok ? '✓ every hash matches the chain' : '✗ mismatch'}</span>{' '}
                  <span className="muted">at {checkedAt}</span>
                </h4>
                <div className="panel">
                  <table className="checks">
                    <thead>
                      <tr>
                        <th>Field</th>
                        <th>Recomputed from the proof</th>
                        <th className="hide-sm">On-chain</th>
                        <th />
                      </tr>
                    </thead>
                    <tbody>
                      {re.checks.map((k) => (
                        <tr key={k.name}>
                          <td>{k.name}</td>
                          <td className="mono">{short(k.recomputed, 8)}</td>
                          <td className="mono hide-sm">{short(k.onchain, 8)}</td>
                          <td className={k.ok ? 'ok' : 'bad'}>{k.ok ? '✓' : '✗'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            ) : null}

            {req && res ? (
              <>
                <section>
                  <h4>Revealed request (auth values stay hidden: *)</h4>
                  <pre className="transcript">{req.head}</pre>
                </section>
                <section>
                  <h4>Revealed response</h4>
                  <pre className="transcript">
                    {res.head}
                    {'\n\n'}
                    {res.body}
                  </pre>
                </section>
              </>
            ) : null}
          </>
        )}
      </aside>
    </>
  )
}

function ReconciliationTab({ calls, info }: { calls: Call[]; info?: Info }) {
  const [recs, setRecs] = useState<Record<string, Reconciliation | string>>({})
  const recent = useMemo(() => [...calls].reverse().slice(0, 30), [calls])
  // Each row is checked once per status, three at a time, newest first. Rows already queued are not
  // queued again when the call list refreshes (every 2 s), so requests never pile up.
  const queued = useRef(new Set<string>())
  useEffect(() => {
    const todo = recent.filter((c) => {
      const done = recs[c.callId]
      const key = `${c.callId}:${c.status}`
      if ((done && typeof done !== 'string' && done.record?.status === c.status) || queued.current.has(key)) return false
      queued.current.add(key)
      return true
    })
    const worker = async () => {
      for (let c = todo.shift(); c; c = todo.shift()) {
        const r = await api.reconcile(c.callId).catch((e: Error) => e.message)
        setRecs((m) => ({ ...m, [c.callId]: r }))
        if (typeof r === 'string') queued.current.delete(`${c.callId}:${c.status}`) // retry on the next refresh
      }
    }
    for (let i = 0; i < 3; i++) void worker()
  }, [recent]) // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <div className="panel">
      <h2>
        Reconciliation from events
        <span className="muted" style={{ fontWeight: 400 }}>
          each call's escrow events against the token's <span className="mono">transfer</span> events in the same transactions
        </span>
      </h2>
      {recent.length === 0 ? <div className="empty">No calls yet.</div> : null}
      <table>
        <tbody>
          {recent.map((c) => {
            const r = recs[c.callId]
            return (
              <tr key={c.callId}>
                <td style={{ width: '32%' }}>
                  <div className="mono">{short(c.callId)}</div>
                  <StatusChip status={c.status} />
                  {r && typeof r !== 'string' ? (
                    <div className={r.ok ? 'ok' : 'bad'} style={{ marginTop: 4 }}>
                      {r.ok ? '✓ reconciles' : '✗ does not reconcile'}
                    </div>
                  ) : null}
                </td>
                <td>
                  {!r ? (
                    <span className="muted">loading…</span>
                  ) : typeof r === 'string' ? (
                    <span className="bad">{r}</span>
                  ) : (
                    <>
                      {r.movements.map((m, i) => (
                        <div key={i} className="num">
                          <Ref value={m.from} info={info} n={4} /> → <Ref value={m.to} info={info} n={4} /> <strong>{amount(m.amount)}</strong>{' '}
                          <Ref value={m.txHash} info={info} />
                        </div>
                      ))}
                      {r.checks
                        .filter((k) => !k.ok)
                        .map((k) => (
                          <div key={k.name} className="bad">
                            ✗ {k.name}
                            {k.detail ? <span className="muted"> · {k.detail}</span> : null}
                          </div>
                        ))}
                      {!r.recordMatches ? <div className="bad">✗ the gateway's record disagrees with the chain</div> : null}
                    </>
                  )}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
      <footer className="foot" style={{ padding: '0 14px 12px' }}>
        Check it yourself: <span className="mono">stellar events --id {info?.escrow ?? '<escrow>'} --start-ledger &lt;hold ledger&gt;</span> lists the escrow's
        events, and the token's <span className="mono">transfer</span> events in the same transactions move the money. RPC keeps events for about 7 days; the
        gateway's index keeps them since it started{info?.indexer?.gaps.length ? ' (with gaps before its start)' : ''}.
      </footer>
    </div>
  )
}

const pct = (x: number | null) => (x === null ? '—' : `${(x * 100).toFixed(x === 1 || x === 0 ? 0 : 1)} %`)

function Snippet({ code, label }: { code: string; label?: string }) {
  const [copied, setCopied] = useState(false)
  const copy = () =>
    navigator.clipboard
      ?.writeText(code)
      .then(() => {
        setCopied(true)
        setTimeout(() => setCopied(false), 1500)
      })
      .catch(() => undefined)
  return (
    <div>
      {label ? <div className="snippet-label">{label}</div> : null}
      <div className="snippet">
        <pre className="transcript">{code}</pre>
        <button className="copy" onClick={() => void copy()} aria-label={`Copy ${label ?? 'the code'}`}>
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
    </div>
  )
}

/** How to pay on proof from your own agent, filled in for this gateway. */
function UseTab({ info, services }: { info?: Info; services?: Service[] }) {
  const origin = typeof location === 'undefined' ? '' : location.origin
  const escrow = info?.escrow ?? 'C…'
  const verifier = info?.verifier ?? '<verifier key>'
  const network = info?.network ?? 'stellar:testnet'
  const svc = services?.[0]
  const paidUrl = svc ? `${origin}${svc.endpoint}${svc.examplePath ?? '/'}` : `${origin}/s/<serviceId>/…`
  const common = `const rpcUrl = '<an RPC URL for ${network}>'
const keypair = Keypair.fromSecret(process.env.AGENT_SECRET!)
const escrows = ['${escrow}']
const trustedVerifiers = ['${verifier}']`
  const mpp = `import { Keypair } from '@stellar/stellar-sdk'
import { Receipt } from 'mppx'
import { Mppx } from 'mppx/client'
import { fermata, type FermataReceipt } from 'fermata-stellar-sdk'

${common}
const mppx = Mppx.create({
  methods: [fermata({ keypair, rpcUrl, network: '${network}', escrows, trustedVerifiers })],
  polyfill: false,
})

// Held in escrow, then released to the vendor on proof, or refunded to you.
const res = await mppx.fetch('${paidUrl}')
const receipt = Receipt.fromResponse(res) as FermataReceipt
console.log(res.status, receipt.outcome, receipt.callId)`
  const x402 = `import { Keypair } from '@stellar/stellar-sdk'
import { wrapFetchWithPaymentFromConfig } from '@x402/fetch'
import { FermataX402Client } from 'fermata-stellar-sdk'

${common}
const pay = wrapFetchWithPaymentFromConfig(fetch, {
  schemes: [{ network: '${network}', client: new FermataX402Client({ keypair, rpcUrl, escrows, trustedVerifiers }) }],
  spendControls: { allowedAssets: true },
})

const res = await pay('${paidUrl}')
console.log(res.status, res.headers.get('x-fermata-outcome'), res.headers.get('x-fermata-call'))`
  return (
    <div className="panel">
      <h2>
        Pay through this gateway <span className="muted">MPP or x402 · testnet · unaudited</span>
      </h2>
      <div className="use">
        <div className="use-grid">
          <section className="use-card">
            <h3>
              MPP: the <span className="mono">fermata</span> method
            </h3>
            <p>
              For <a href="https://github.com/wevm/mppx" target="_blank" rel="noreferrer">mppx</a> (0.10). By default you sign only the hold's
              authorization and the gateway submits it and pays the fee; <span className="mono">mode: 'direct'</span> submits it from your account.
            </p>
            <Snippet label="Pay one call" code={mpp} />
          </section>
          <section className="use-card">
            <h3>
              x402: the <span className="mono">fermata</span> scheme
            </h3>
            <p>
              For any x402 v2 client, such as <span className="mono">@x402/fetch</span>. You sign the hold's authorization; the gateway's facilitator submits it.
            </p>
            <Snippet label="Pay one call" code={x402} />
          </section>
        </div>
        <div className="note">
          <span className="mono">fermata-stellar-sdk</span> is <span className="mono">packages/sdk</span> in this repository; it is not published on npm. Before any money
          moves, both clients check the escrow and the verifier against your lists, the registered price, and your limits (
          <span className="mono">maxAmount</span>, <span className="mono">maxSettlementWindow</span>).
        </div>
        <div className="links">
          <a href="/llms.txt" target="_blank" rel="noreferrer">
            llms.txt
          </a>
          <a href="/openapi.json" target="_blank" rel="noreferrer">
            OpenAPI
          </a>
        </div>
      </div>
      <footer className="foot" style={{ padding: '0 14px 12px' }}>
        The escrow and verifier above are this gateway's. In your agent they are your own allow-lists: an agent never pays a verifier just because a gateway names it,
        so pin them from a source you trust, and pay only gateways you trust.
      </footer>
    </div>
  )
}

/** Every vendor's proven delivery record, from the escrow's indexed events only (GET /scores). */
function VendorsTab({ scores, info }: { scores?: Scores; info?: Info }) {
  if (!scores) return <div className="empty">Loading…</div>
  const rows = scores.scores
  return (
    <div className="panel">
      <h2>
        Vendor scores <span className="muted">proven delivery, from on-chain events</span>
      </h2>
      {rows.length === 0 ? (
        <div className="empty">No calls yet.</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Vendor</th>
              <th>Delivered</th>
              <th>Score</th>
              <th className="hide-sm">Proven failures</th>
              <th className="hide-sm">Timeouts</th>
              <th className="hide-sm">Agents</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((s, i) => (
              <tr key={s.serviceId}>
                <td className="num muted">{i + 1}</td>
                <td>
                  <div>
                    {serviceName(s.serviceId, s.summary)}
                    {s.fewCalls ? (
                      <span className="badge" style={{ marginLeft: 8 }}>
                        few calls
                      </span>
                    ) : null}
                  </div>
                  <div className="mono muted origin" title={s.serviceId}>
                    {s.upstream ?? short(s.serviceId, 8)}
                  </div>
                </td>
                <td className="num">
                  {s.released}/{s.settled} <span className="muted hide-sm">({pct(s.deliveryRate)})</span>
                  {s.open ? <div className="muted">{s.open} open</div> : null}
                </td>
                <td className="num">
                  <b>{pct(s.score)}</b>
                </td>
                <td className="hide-sm num">{s.provenFailures}</td>
                <td className="hide-sm num">{s.timeouts}</td>
                <td className="hide-sm num">{s.distinctAgents}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <footer className="foot" style={{ padding: '0 14px 12px' }}>
        Score = Wilson 95 % lower bound of delivered ÷ (delivered + proven failures), so 3/3 does not outrank 950/1000. Proven failure = refunded on the vendor's own
        proved answer; timeout = no proof in the window. {scores.caveats.join(' ')}
        {info?.explorer ? (
          <>
            {' '}
            · escrow <Ref value={scores.escrow} info={info} />
          </>
        ) : null}
      </footer>
    </div>
  )
}

function ServicesTab({ services, info }: { services?: Service[]; info?: Info }) {
  if (!services) return <div className="empty">Loading…</div>
  return (
    <div className="panel">
      <h2>Registered services</h2>
      <table>
        <thead>
          <tr>
            <th>Service</th>
            <th className="hide-sm">Upstream</th>
            <th>Price</th>
            <th className="hide-sm">Window</th>
            <th className="hide-sm">Pay with</th>
          </tr>
        </thead>
        <tbody>
          {services.map((s) => (
            <tr key={s.serviceId}>
              <td>
                <div>{serviceName(s.serviceId, s.summary)}</div>
                <div className="mono muted">{short(s.serviceId, 8)}</div>
              </td>
              <td className="hide-sm mono">{s.upstream}</td>
              <td className="num">
                {amount(s.price)} <Ref value={s.token} info={info} n={4} />
              </td>
              <td className="hide-sm num">{s.settlementWindow} s</td>
              <td className="hide-sm">
                MPP: {s.pay.mpp.join(', ')}
                <br />
                x402: {s.pay.x402.join(', ') || '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <footer className="foot" style={{ padding: '0 14px 12px' }}>
        Escrow <Ref value={info?.escrow} info={info} n={8} /> on {info?.network ?? '…'}
      </footer>
    </div>
  )
}

export function App() {
  const [tab, setTab] = useState<Tab>(() => (location.hash.slice(1) as Tab) || 'live')
  const [open, setOpen] = useState<Call>()
  const info = usePoll(api.info, 30_000).data
  const { data: calls = [], error } = usePoll(api.calls, 2_000)
  const events = usePoll(api.events, 2_000).data ?? []
  const services = usePoll(api.services, 30_000).data
  const scores = usePoll(api.scores, 10_000).data
  useEffect(() => {
    location.hash = tab
  }, [tab])
  // In-page links switch tabs.
  useEffect(() => {
    const follow = () => setTab((location.hash.slice(1) as Tab) || 'live')
    addEventListener('hashchange', follow)
    return () => removeEventListener('hashchange', follow)
  }, [])
  const openCall = open ? (calls.find((c) => c.callId === open.callId) ?? open) : undefined
  const networkName = info ? (info.explorer ? 'Stellar testnet' : `local network (${info.network})`) : '…'
  return (
    <div className="shell">
      <header className="top">
        <div className="brand">
          <Fermata />
          <h1>Fermata</h1>
          <span className="tag">pay on proof · Stellar</span>
        </div>
        <span className="badge">
          <span className="dot" style={{ background: error ? 'var(--critical)' : undefined }} />
          {error ? 'gateway unreachable' : networkName}
        </span>
        <span className="badge mono" title={info?.escrow}>
          escrow {short(info?.escrow)}
        </span>
        <ThemeToggle />
      </header>
      <Tiles calls={calls} services={services} />
      <nav className="tabs" role="tablist">
        {(
          [
            ['live', 'Live'],
            ['vendors', 'Vendors'],
            ['use', 'Use it'],
            ['reconciliation', 'Reconciliation'],
            ['services', 'Services'],
          ] as const
        ).map(([id, label]) => (
          <button key={id} role="tab" aria-selected={tab === id} onClick={() => setTab(id)}>
            {label}
          </button>
        ))}
      </nav>
      {tab === 'live' ? <LiveTab calls={calls} events={events} services={services} info={info} onOpen={setOpen} /> : null}
      {tab === 'reconciliation' ? <ReconciliationTab calls={calls} info={info} /> : null}
      {tab === 'vendors' ? <VendorsTab scores={scores} info={info} /> : null}
      {tab === 'use' ? <UseTab info={info} services={services} /> : null}
      {tab === 'services' ? <ServicesTab services={services} info={info} /> : null}
      <footer className="foot">
        A disclosed verifier signs each verdict; every verdict points at a TLSNotary presentation anyone can download and re-verify offline. The proof shows what the
        vendor's server sent, not that the data is correct. Testnet only, unaudited.
      </footer>
      {openCall ? <CallDrawer call={openCall} info={info} onClose={() => setOpen(undefined)} /> : null}
    </div>
  )
}

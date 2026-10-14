// Ported from Fermata apps/dashboard/src/format.ts @ d7cc642 (github.com/bilgin-kocak/fermata, MIT).
// Changed for Stellar: amounts have 7 decimals; a service id is a hash with no label inside; the
// `holding` status; stellar.expert paths for transactions, contracts and accounts.
import type { CallStatus } from './api.ts'

export const short = (h?: string | null, n = 6) => (!h ? '—' : h.length <= 2 * n + 1 ? h : `${h.slice(0, n)}…${h.slice(-4)}`)

/** Token base units (7 decimals) → exact decimal, at least 2 places: 100000 → "0.01", 99500 → "0.00995". */
export const amount = (units: string | number | bigint, digits?: number) => {
  const v = Number(units) / 1e7
  if (digits !== undefined) return v.toFixed(digits)
  return v.toFixed(7).replace(/(\.\d\d\d*?)0+$/, '$1')
}

export const compact = (n: number) =>
  n >= 1e9 ? `${(n / 1e9).toFixed(1)}G` : n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e3 ? `${(n / 1e3).toFixed(1)}K` : String(n)

export function age(iso: string, now = Date.now()) {
  const s = Math.max(0, Math.round((now - Date.parse(iso)) / 1000))
  return s < 60 ? `${s}s ago` : s < 3600 ? `${Math.floor(s / 60)}m ago` : `${Math.floor(s / 3600)}h ago`
}

/** A Stellar service id is sha256 of the owner and the label: the summary names it, else its prefix. */
export const serviceName = (serviceId: string, summary?: string | null) => summary ?? short(serviceId, 8)

/** An explorer link for a transaction hash, a contract (C…) or an account (G…). */
export function explorerUrl(explorer: string, ref: string) {
  if (/^C[A-Z2-7]{55}$/.test(ref)) return `${explorer}/contract/${ref}`
  if (/^G[A-Z2-7]{55}$/.test(ref)) return `${explorer}/account/${ref}`
  return `${explorer}/tx/${ref}`
}

/** Status → reserved status role + icon + label (never color alone). */
export const STATUS: Record<CallStatus, { role: 'good' | 'warning' | 'serious' | 'critical' | 'neutral'; icon: string; label: string }> = {
  holding: { role: 'neutral', icon: '…', label: 'Holding' },
  held: { role: 'neutral', icon: '●', label: 'Held — proving' },
  released: { role: 'good', icon: '✓', label: 'Released' },
  refunded: { role: 'serious', icon: '↩', label: 'Refunded (verified failure)' },
  'settle-pending': { role: 'warning', icon: '⟳', label: 'Settle pending' },
  'awaiting-timeout': { role: 'warning', icon: '⏳', label: 'No proof — awaiting timeout' },
  'timed-out': { role: 'serious', icon: '⏱', label: 'Refunded (timeout)' },
  closed: { role: 'neutral', icon: '■', label: 'Closed' },
}

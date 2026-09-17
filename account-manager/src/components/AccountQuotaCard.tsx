import InitialMark from '@/components/InitialMark'
import type {
  ProviderDescriptor,
  ProviderQuotaList,
  QuotaSnapshot,
} from '@/types'

export type QuotaView = 'list' | 'grid'

/**
 * One account's identity, sourced remaining quota, and reset time on a
 * single surface. A percentage and bar appear only from a finite 0..1
 * utilization (`FR-5`, `NFR-8`).
 */
export default function AccountQuotaCard({
  provider,
  accountId,
  displayName,
  planLabel,
  snapshots,
  result,
  requestError,
  loading,
  view,
}: {
  provider: ProviderDescriptor
  accountId: string
  displayName: string
  planLabel: string | null
  snapshots: QuotaSnapshot[]
  result: ProviderQuotaList | undefined
  requestError: string | null
  loading: boolean
  view: QuotaView
}) {
  const plan = planLabel?.trim() ?? ''
  const reset = resetTimestamp(snapshots)

  return (
    <article
      data-provider={provider.id}
      data-account={accountId}
      className={`panel provider-block h-full p-4 ${
        view === 'list'
          ? 'md:grid md:grid-cols-[minmax(12rem,1.1fr)_minmax(12rem,1.4fr)_minmax(8rem,0.9fr)] md:items-start md:gap-6'
          : ''
      }`}
      aria-label={`${displayName} quota`}
    >
      <header className="flex items-start gap-3">
        <InitialMark name={displayName} />
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="font-semibold tracking-tight">{displayName}</h3>
            <span className="provider-chip">{provider.displayName}</span>
            {plan !== '' && <span className="chip chip-muted">{plan}</span>}
          </div>
        </div>
      </header>
      <div className={view === 'list' ? 'mt-3 md:mt-0' : 'mt-3'}>
        <QuotaUsage
          snapshots={snapshots}
          result={result}
          requestError={requestError}
          loading={loading}
        />
      </div>
      <p className={`text-sm ${view === 'list' ? 'mt-3 md:mt-0' : 'mt-3'}`}>
        <span className="text-ink-muted">Reset </span>
        {loading ? (
          <span className="text-ink-muted">…</span>
        ) : reset === null ? (
          <>—</>
        ) : (
          <Timestamp value={reset} />
        )}
      </p>
    </article>
  )
}

function QuotaUsage({
  snapshots,
  result,
  requestError,
  loading,
}: {
  snapshots: QuotaSnapshot[]
  result: ProviderQuotaList | undefined
  requestError: string | null
  loading: boolean
}) {
  if (loading) {
    return <p className="text-sm text-ink-muted">Checking quota signal…</p>
  }
  if (requestError !== null) {
    return <QuotaFailure message={`Quota collection failed: ${requestError}`} />
  }
  if (result === undefined) {
    return <QuotaFailure message="Quota result missing for this provider." />
  }
  if (result.outcome.kind === 'failed') {
    return (
      <QuotaFailure
        message={`Quota collection failed: ${result.outcome.error.message}`}
      />
    )
  }
  if (result.outcome.kind === 'no-signal' || snapshots.length === 0) {
    return <p className="text-sm text-ink-muted">No quota signal available</p>
  }

  return (
    <ul className="space-y-3" aria-label="Sourced quota snapshots">
      {snapshots.map((snapshot, index) => (
        <li
          key={`${snapshot.accountId}-${snapshot.model ?? 'all'}-${snapshot.capturedAt}-${index}`}
        >
          <SnapshotUsage snapshot={snapshot} />
        </li>
      ))}
    </ul>
  )
}

function SnapshotUsage({ snapshot }: { snapshot: QuotaSnapshot }) {
  const remaining = remainingPercent(snapshot.utilization)
  if (remaining === null) {
    return <QuotaFailure message="Invalid utilization in quota snapshot." />
  }

  const windowLabel = snapshot.windowLabel?.trim() ?? ''

  return (
    <div className="text-sm">
      <p className="text-base font-semibold">
        {formatPercentage(remaining)} remaining
      </p>
      <RemainingBar remaining={remaining} />
      {windowLabel !== '' && (
        <p className="mt-1 text-ink-muted">{windowLabel}</p>
      )}
    </div>
  )
}

function RemainingBar({ remaining }: { remaining: number }) {
  const width = Math.min(100, Math.max(0, remaining))
  return (
    <div
      className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-surface-sunken"
      role="progressbar"
      aria-label="Remaining quota"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={Math.round(width)}
    >
      <div
        className={`h-full ${barTone(remaining)}`}
        style={{ width: `${width}%` }}
      />
    </div>
  )
}

function QuotaFailure({ message }: { message: string }) {
  return (
    <p className="notice notice-danger" role="alert">
      {message}
    </p>
  )
}

function Timestamp({ value }: { value: string }) {
  const timestamp = Date.parse(value)
  if (!Number.isFinite(timestamp)) {
    return <span>Invalid timestamp ({value})</span>
  }
  return (
    <time dateTime={value} title={value}>
      {new Date(timestamp).toLocaleString()}
    </time>
  )
}

function resetTimestamp(snapshots: QuotaSnapshot[]): string | null {
  for (const snapshot of snapshots) {
    if (snapshot.resetsAt !== null && snapshot.resetsAt !== '') {
      return snapshot.resetsAt
    }
  }
  return null
}

function remainingPercent(utilization: number): number | null {
  if (!Number.isFinite(utilization) || utilization < 0 || utilization > 1) {
    return null
  }
  return (1 - utilization) * 100
}

function formatPercentage(value: number): string {
  return `${new Intl.NumberFormat('en-US', { maximumFractionDigits: 2 }).format(value)}%`
}

function barTone(remaining: number): string {
  if (remaining >= 50) return 'bg-ok'
  if (remaining >= 20) return 'bg-warn'
  return 'bg-danger'
}

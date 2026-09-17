import { useEffect, useState } from 'react'
import { accountDisplayName } from '@/components/AccountActions'
import AccountQuotaCard, { type QuotaView } from '@/components/AccountQuotaCard'
import PageHeader from '@/components/PageHeader'
import { listAccounts, listProviders, listQuota } from '@/lib/tauri'
import type {
  ProviderAccountList,
  ProviderDescriptor,
  ProviderQuotaList,
} from '@/types'

/** Per-account quota rows in list and grid views (`FR-5`, `NFR-8`). */
export default function Dashboard() {
  const [providers, setProviders] = useState<ProviderDescriptor[]>([])
  const [listings, setListings] = useState<ProviderAccountList[]>([])
  const [summaryError, setSummaryError] = useState<string | null>(null)
  const [summaryLoading, setSummaryLoading] = useState(true)
  const [quota, setQuota] = useState<ProviderQuotaList[]>([])
  const [quotaError, setQuotaError] = useState<string | null>(null)
  const [quotaLoading, setQuotaLoading] = useState(true)
  const [quotaView, setQuotaView] = useState<QuotaView>('grid')

  useEffect(() => {
    let cancelled = false

    Promise.allSettled([
      Promise.resolve().then(listProviders),
      Promise.resolve().then(() => listAccounts()),
    ]).then(([providerResult, listingResult]) => {
      if (cancelled) return

      const failures: string[] = []
      if (providerResult.status === 'fulfilled') {
        setProviders(providerResult.value)
      } else {
        failures.push(`providers: ${String(providerResult.reason)}`)
      }
      if (listingResult.status === 'fulfilled') {
        setListings(listingResult.value)
      } else {
        failures.push(`accounts: ${String(listingResult.reason)}`)
      }
      setSummaryError(failures.length === 0 ? null : failures.join('; '))
      setSummaryLoading(false)
    })

    Promise.resolve()
      .then(listQuota)
      .then((nextQuota) => {
        if (cancelled) return
        setQuota(nextQuota)
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setQuotaError(String(cause))
      })
      .finally(() => {
        if (cancelled) return
        setQuotaLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [])

  const rows = accountQuotaRows(providers, listings)
  const statusNotes = adapterStatusNotes(providers, listings, quota)

  return (
    <>
      <PageHeader
        title="Dashboard"
        description="Each account shows remaining quota and reset time when a snapshot exists. Otherwise the row stays and says so."
      />
      {summaryLoading && (
        <p className="text-sm text-ink-muted" role="status">
          Loading summary…
        </p>
      )}
      {summaryError !== null && (
        <p className="notice notice-danger mb-4" role="alert">
          Failed to load dashboard summary: {summaryError}
        </p>
      )}
      {statusNotes.length > 0 && (
        <ul
          className="notice notice-warn mb-4 space-y-1"
          aria-label="Adapter status"
        >
          {statusNotes.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      )}
      {!summaryLoading && providers.length === 0 && (
        <p className="text-sm text-ink-muted">No providers were returned.</p>
      )}

      <section className="mt-2" aria-labelledby="quota-heading">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2
              id="quota-heading"
              className="text-lg font-semibold tracking-tight"
            >
              Account quota
            </h2>
            <p className="mt-1 text-sm text-ink-muted">
              Remaining quota is derived only from sourced utilization.
            </p>
          </div>
          <div
            className="flex rounded-md border border-border-subtle bg-surface p-1"
            role="group"
            aria-label="Quota view"
          >
            <ViewButton
              selected={quotaView === 'list'}
              onClick={() => setQuotaView('list')}
            >
              List
            </ViewButton>
            <ViewButton
              selected={quotaView === 'grid'}
              onClick={() => setQuotaView('grid')}
            >
              Grid
            </ViewButton>
          </div>
        </div>

        {quotaLoading && (
          <p className="mt-4 text-sm text-ink-muted" role="status">
            Loading quota…
          </p>
        )}
        {!summaryLoading && providers.length > 0 && rows.length === 0 && (
          <p className="mt-4 text-sm text-ink-muted">
            No accounts are listed, so there is no quota row to show.
          </p>
        )}
        {!summaryLoading && rows.length > 0 && (
          <ul
            className={
              quotaView === 'grid'
                ? 'mt-4 grid gap-4 md:grid-cols-2'
                : 'mt-4 space-y-3'
            }
            aria-label={quotaView === 'grid' ? 'Quota grid' : 'Quota list'}
          >
            {rows.map((row) => {
              const result = quota.find(
                (candidate) => candidate.providerId === row.provider.id,
              )
              return (
                <li key={row.key}>
                  <AccountQuotaCard
                    provider={row.provider}
                    accountId={row.accountId}
                    displayName={row.displayName}
                    planLabel={result?.planLabel ?? null}
                    snapshots={snapshotsFor(result, row.accountId)}
                    result={result}
                    requestError={quotaError}
                    loading={quotaLoading}
                    view={quotaView}
                  />
                </li>
              )
            })}
          </ul>
        )}
      </section>
    </>
  )
}

function ViewButton({
  selected,
  onClick,
  children,
}: {
  selected: boolean
  onClick: () => void
  children: string
}) {
  return (
    <button
      type="button"
      className={`rounded px-3 py-1.5 text-sm focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent ${
        selected
          ? 'bg-surface-raised font-medium text-ink ring-1 ring-accent'
          : 'text-ink-muted hover:text-ink'
      }`}
      aria-pressed={selected}
      onClick={onClick}
    >
      {children}
    </button>
  )
}

type AccountQuotaRow = {
  key: string
  provider: ProviderDescriptor
  accountId: string
  displayName: string
}

function accountQuotaRows(
  providers: ProviderDescriptor[],
  listings: ProviderAccountList[],
): AccountQuotaRow[] {
  const rows: AccountQuotaRow[] = []
  for (const provider of providers) {
    const listing = listings.find((item) => item.providerId === provider.id)
    if (listing === undefined) continue
    for (const account of listing.accounts) {
      rows.push({
        key: `${provider.id}:${account.id}`,
        provider,
        accountId: account.id,
        displayName: accountDisplayName(account),
      })
    }
  }
  return rows
}

function snapshotsFor(
  result: ProviderQuotaList | undefined,
  accountId: string,
): ProviderQuotaList['snapshots'] {
  if (result === undefined) return []
  return result.snapshots.filter((snapshot) => snapshot.accountId === accountId)
}

function adapterStatusNotes(
  providers: ProviderDescriptor[],
  listings: ProviderAccountList[],
  quota: ProviderQuotaList[],
): string[] {
  const notes: string[] = []
  for (const listing of listings) {
    const name = providerName(providers, listing.providerId)
    switch (listing.outcome.kind) {
      case 'failed':
        notes.push(`${name}: looking failed — ${listing.outcome.error.message}`)
        break
      case 'listed-with-error':
        notes.push(`${name}: ${listing.outcome.error.message}`)
        break
      case 'not-implemented':
        notes.push(`${name}: this adapter cannot list accounts yet.`)
        break
      default:
        break
    }
  }
  for (const result of quota) {
    if (result.outcome.kind !== 'failed') continue
    const listing = listings.find(
      (item) => item.providerId === result.providerId,
    )
    if (listing !== undefined && listing.accounts.length > 0) continue
    notes.push(
      `${providerName(providers, result.providerId)}: quota collection failed — ${result.outcome.error.message}`,
    )
  }
  return notes
}

function providerName(
  providers: ProviderDescriptor[],
  providerId: string,
): string {
  return (
    providers.find((provider) => provider.id === providerId)?.displayName ??
    providerId
  )
}

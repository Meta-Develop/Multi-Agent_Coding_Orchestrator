import {
  Fragment,
  useEffect,
  useState,
  type ReactElement,
  type ReactNode,
} from 'react'
import AccountActions, {
  Confirmation,
  accountDisplayName,
  type PendingKind,
} from '@/components/AccountActions'
import AddAccountForm from '@/components/AddAccountForm'
import InitialMark from '@/components/InitialMark'
import NotImplemented from '@/components/NotImplemented'
import PageHeader from '@/components/PageHeader'
import {
  useAccountMutation,
  type PendingConfirmation,
} from '@/lib/accountMutation'
import { listAccounts, listProviders } from '@/lib/tauri'
import type {
  Account,
  AuthKind,
  ProviderAccountList,
  ProviderCapability,
  ProviderDescriptor,
} from '@/types'

/**
 * Lists accounts from every adapter, grouped by provider. Empty, unfinished,
 * failed, listed-with-error, and API-key-only listings are distinct (`NFR-8`).
 * Add appears when the adapter advertises it. Activation is presented either
 * as a legacy tool-wide switch or as selection for an app-owned launch. Delete
 * appears when the adapter advertises it and the row is stored, including
 * incomplete slots (`FR-1`, `NFR-8`).
 */
export default function Accounts() {
  const [providers, setProviders] = useState<ProviderDescriptor[]>([])
  const [listings, setListings] = useState<ProviderAccountList[]>([])
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const {
    busy,
    pending,
    listingEpoch,
    requestPending,
    cancelPending,
    runMutation,
    runLaunch,
  } = useAccountMutation()

  useEffect(() => {
    let cancelled = false
    Promise.all([listProviders(), listAccounts()])
      .then(([nextProviders, nextListings]) => {
        if (cancelled) return
        setProviders(nextProviders)
        setListings(nextListings)
        setError(null)
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        // A reload after a successful mutation must not blank a listing
        // the user can still act on. The page-level error is only for
        // the first look.
        if (listingEpoch === 0) {
          setError(String(cause))
        }
      })
      .finally(() => {
        if (cancelled) return
        setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [listingEpoch])

  const cannotSelectOrSwitch = providers.filter(
    (provider) =>
      !hasCapability(provider, 'switch-account') &&
      !hasCapability(provider, 'launch-tool'),
  )

  function handleConfirmPending() {
    if (pending === null) return
    const provider = providers.find((item) => item.id === pending.providerId)
    if (provider === undefined) {
      cancelPending()
      return
    }
    const listing = listingFor(listings, pending.providerId)
    const account = listing?.accounts.find(
      (item) => item.id === pending.accountId,
    )
    const accountName =
      account === undefined ? pending.accountId : accountDisplayName(account)
    void runMutation(
      pending.kind,
      provider,
      pending.accountId,
      accountName,
      pending.authKind ?? account?.authKind,
    )
  }

  return (
    <>
      <PageHeader
        title="Accounts"
        description="Every account this application can see, grouped by provider. Some adapters switch the tool itself; launch-selected adapters change only which account this application uses for a child process it launches."
      />
      {loading && (
        <p className="text-sm text-ink-muted" role="status">
          Loading accounts…
        </p>
      )}
      {error !== null && (
        <p className="notice notice-danger mb-4">
          Failed to load accounts: {error}
        </p>
      )}
      {!loading && error === null && (
        <div className="space-y-10" aria-busy={busy}>
          {providers.length === 0 && (
            <p className="text-sm text-ink-muted">
              No providers were returned.
            </p>
          )}
          {providers.map((provider) => (
            <ProviderAccounts
              key={provider.id}
              provider={provider}
              listing={listingFor(listings, provider.id)}
              busy={busy}
              pending={
                pending !== null && pending.providerId === provider.id
                  ? pending
                  : null
              }
              onAdd={(accountId, authKind) =>
                runMutation('add', provider, accountId, accountId, authKind)
              }
              onLaunch={(account) => {
                void runLaunch(provider, accountDisplayName(account))
              }}
              onRequest={(accountId, kind, authKind) =>
                requestPending({
                  providerId: provider.id,
                  accountId,
                  kind,
                  ...(authKind === undefined ? {} : { authKind }),
                })
              }
              onCancelPending={cancelPending}
              onConfirmPending={handleConfirmPending}
            />
          ))}
          {cannotSelectOrSwitch.length > 0 && (
            <NotImplemented requirement="FR-1">
              {cannotSelectOrSwitch
                .map((provider) => provider.displayName)
                .join(', ')}{' '}
              cannot switch accounts or select an account for app launch yet.
              This page only lists what those adapters can see.
            </NotImplemented>
          )}
        </div>
      )}
    </>
  )
}

function ProviderAccounts({
  provider,
  listing,
  busy,
  pending,
  onAdd,
  onLaunch,
  onRequest,
  onCancelPending,
  onConfirmPending,
}: {
  provider: ProviderDescriptor
  listing: ProviderAccountList | undefined
  busy: boolean
  pending: PendingConfirmation | null
  onAdd: (accountId: string, authKind?: AuthKind) => Promise<boolean>
  onLaunch: (account: Account) => void
  onRequest: (accountId: string, kind: PendingKind, authKind?: AuthKind) => void
  onCancelPending: () => void
  onConfirmPending: () => void
}) {
  const headingId = `accounts-heading-${provider.id}`
  const canAdd = hasCapability(provider, 'add-account')
  const canSwitch = hasCapability(provider, 'switch-account')
  const canLaunch = hasCapability(provider, 'launch-tool')
  const canDelete = hasCapability(provider, 'delete-account')

  return (
    <section
      aria-labelledby={headingId}
      data-provider={provider.id}
      className="provider-block"
    >
      <div className="flex items-start gap-3">
        <InitialMark name={provider.displayName} />
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <h2
              id={headingId}
              className="text-base font-semibold tracking-tight"
            >
              {provider.displayName}
            </h2>
            <span className="provider-chip">{provider.vendor}</span>
          </div>
          <p className="mt-1 text-xs text-ink-muted">{provider.maturity}</p>
        </div>
      </div>
      {listingBody({
        headingId,
        listing,
        provider,
        busy,
        pending,
        canSwitch,
        canLaunch,
        canDelete,
        onRequest,
        onLaunch,
        onCancelPending,
        onConfirmPending,
      })}
      {canAdd && listingHasUnstored(listing) && (
        <p className="mt-3 text-sm text-ink-muted">
          {canLaunch
            ? "The tool's current identity is not stored here, so this application cannot select it for an app-owned launch."
            : "The tool's current identity is not stored here, so this application cannot switch back to it."}
        </p>
      )}
      {canAdd && (
        <AddAccountForm provider={provider} disabled={busy} onAdd={onAdd} />
      )}
    </section>
  )
}

function listingBody({
  headingId,
  listing,
  provider,
  busy,
  pending,
  canSwitch,
  canLaunch,
  canDelete,
  onRequest,
  onLaunch,
  onCancelPending,
  onConfirmPending,
}: {
  headingId: string
  listing: ProviderAccountList | undefined
  provider: ProviderDescriptor
  busy: boolean
  pending: PendingConfirmation | null
  canSwitch: boolean
  canLaunch: boolean
  canDelete: boolean
  onRequest: (accountId: string, kind: PendingKind, authKind?: AuthKind) => void
  onLaunch: (account: Account) => void
  onCancelPending: () => void
  onConfirmPending: () => void
}): ReactElement {
  if (listing === undefined) {
    return (
      <p className="mt-3 text-sm text-ink-muted">
        No listing was returned for this provider.
      </p>
    )
  }

  const table = (accounts: Account[]) => (
    <AccountTable
      headingId={headingId}
      accounts={accounts}
      provider={provider}
      busy={busy}
      pending={pending}
      canSwitch={canSwitch}
      canLaunch={canLaunch}
      canDelete={canDelete}
      onRequest={onRequest}
      onLaunch={onLaunch}
      onCancelPending={onCancelPending}
      onConfirmPending={onConfirmPending}
    />
  )

  switch (listing.outcome.kind) {
    case 'listed':
      if (listing.accounts.length === 0) {
        return (
          <p className="mt-3 text-sm text-ink-muted">
            Nothing is configured for this provider on this machine.
          </p>
        )
      }
      return table(listing.accounts)
    case 'listed-api-key-only':
      if (listing.accounts.length === 0) {
        return (
          <LimitationNote>
            No stored API-key account is available. This listing does not
            include other auth kinds.
          </LimitationNote>
        )
      }
      return (
        <>
          {table(listing.accounts)}
          <LimitationNote>
            This adapter lists API-key accounts only.
          </LimitationNote>
        </>
      )
    case 'listed-with-error':
      return (
        <>
          <DamagedLiveFileNote
            provider={provider}
            message={listing.outcome.error.message}
            path={listing.outcome.error.path}
          />
          {listing.accounts.length > 0 ? (
            table(listing.accounts)
          ) : (
            <p className="mt-3 text-sm text-ink-muted">
              No stored copy is available to switch over the damaged file.
            </p>
          )}
        </>
      )
    case 'not-implemented':
      return (
        <LimitationNote>This adapter cannot list accounts yet.</LimitationNote>
      )
    case 'failed':
      return (
        <p className="notice notice-danger mt-3">
          Looking failed: {listing.outcome.error.message}
        </p>
      )
    default: {
      const _exhaustive: never = listing.outcome
      return _exhaustive
    }
  }
}

/**
 * A successful look that also found a damaged live login file. The
 * stored rows are the repair path (SPEC §7): switch one of them over
 * the file. This is the opposite of `failed`, which hides the table.
 */
function DamagedLiveFileNote({
  provider,
  message,
  path,
}: {
  provider: ProviderDescriptor
  message: string
  path: string | null
}) {
  return (
    <div className="notice notice-warn mt-3">
      <p>
        {provider.displayName}&apos;s own login file is damaged, so this
        application cannot tell which account the tool would use. Switching a
        stored copy over that file (behind a restorable backup) is the recovery
        path. This application will not rewrite a file it does not understand.
      </p>
      <p className="mt-2 text-ink-muted">{textWithPath(message, path)}</p>
    </div>
  )
}

function LimitationNote({ children }: { children: React.ReactNode }) {
  return (
    <div className="notice notice-empty mt-3">
      <p className="text-sm">{children}</p>
    </div>
  )
}

function AccountTable({
  headingId,
  accounts,
  provider,
  busy,
  pending,
  canSwitch,
  canLaunch,
  canDelete,
  onRequest,
  onLaunch,
  onCancelPending,
  onConfirmPending,
}: {
  headingId: string
  accounts: Account[]
  provider: ProviderDescriptor
  busy: boolean
  pending: PendingConfirmation | null
  canSwitch: boolean
  canLaunch: boolean
  canDelete: boolean
  onRequest: (accountId: string, kind: PendingKind, authKind?: AuthKind) => void
  onLaunch: (account: Account) => void
  onCancelPending: () => void
  onConfirmPending: () => void
}) {
  const unknownActiveId = `${headingId}-unknown-active`
  const activeKnown = accounts.some((account) => account.isActive)
  const showExpires = accounts.some(hasExpiry)
  const showActions = accounts.some(
    (account) =>
      (canSwitch && account.isStored && !account.isIncomplete) ||
      (canLaunch &&
        account.isStored &&
        !account.isIncomplete &&
        account.isSelectedForLaunch) ||
      (canDelete && account.isStored),
  )
  const columnCount = 4 + (showExpires ? 1 : 0) + (showActions ? 1 : 0)

  return (
    <>
      {!activeKnown && (
        <p id={unknownActiveId} className="mt-3 text-sm text-ink-muted">
          Active account is not known for this provider.
        </p>
      )}
      <div className="table-frame mt-3 w-0 min-w-full overflow-x-auto">
        <table
          className="accounts-table text-left text-sm"
          aria-labelledby={headingId}
          aria-describedby={activeKnown ? undefined : unknownActiveId}
        >
          <colgroup>
            <col className="col-label" />
            <col className="col-identity" />
            <col className="col-auth" />
            <col className="col-status" />
            {showExpires && <col className="col-expires" />}
            {showActions && <col className="col-actions" />}
          </colgroup>
          <thead className="text-xs uppercase tracking-wide text-ink-muted">
            <tr>
              <th scope="col" className="py-2 pr-3 pl-3">
                Label
              </th>
              <th scope="col" className="py-2 pr-3">
                Identity
              </th>
              <th scope="col" className="py-2 pr-3">
                Auth
              </th>
              <th
                scope="col"
                className={showExpires || showActions ? 'py-2 pr-3' : 'py-2'}
              >
                Status
              </th>
              {showExpires && (
                <th scope="col" className={showActions ? 'py-2 pr-3' : 'py-2'}>
                  Expires
                </th>
              )}
              {showActions && (
                <th scope="col" className="py-2">
                  Actions
                </th>
              )}
            </tr>
          </thead>
          <tbody>
            {accounts.map((account) => {
              const labelId = `${headingId}-label-${account.id}`
              const rowId = `${headingId}-row-${account.id}`
              const confirmId = `${headingId}-confirm-${account.id}`
              const confirmRowId = `${headingId}-confirm-row-${account.id}`
              const isPending =
                pending !== null && pending.accountId === account.id
              const pendingKind = isPending ? pending.kind : null

              return (
                <Fragment key={account.id}>
                  <tr
                    id={rowId}
                    className={accountRowClass(account.isActive)}
                    aria-owns={isPending ? confirmRowId : undefined}
                    aria-describedby={isPending ? confirmId : undefined}
                  >
                    <th
                      id={labelId}
                      scope="row"
                      className="py-2 pr-3 pl-3 text-left font-medium"
                      title={
                        account.label.trim() === '' ? undefined : account.label
                      }
                    >
                      {presentOrAbsent(account.label, 'No label')}
                    </th>
                    <td className="py-2 pr-3 text-ink-muted">
                      {account.isIncomplete
                        ? 'No usable credential'
                        : presentOrAbsent(
                            account.maskedIdentity,
                            'Not established',
                          )}
                    </td>
                    <td className="py-2 pr-3 whitespace-nowrap text-ink-muted">
                      {account.authKind}
                    </td>
                    <td
                      className={
                        showExpires || showActions
                          ? 'py-2 pr-3 whitespace-nowrap'
                          : 'py-2 whitespace-nowrap'
                      }
                    >
                      {statusCell(account, activeKnown)}
                    </td>
                    {showExpires && (
                      <td
                        className={
                          showActions
                            ? 'py-2 pr-3 text-ink-muted'
                            : 'py-2 text-ink-muted'
                        }
                      >
                        {formatExpiry(account.expiresAt)}
                      </td>
                    )}
                    {showActions && (
                      <td className="py-2 whitespace-nowrap">
                        {pendingKind === null && (
                          <AccountActions
                            account={account}
                            canSwitch={
                              canSwitch &&
                              account.isStored &&
                              !account.isIncomplete &&
                              (!canLaunch || !account.isSelectedForLaunch)
                            }
                            canLaunch={
                              canLaunch &&
                              account.isStored &&
                              !account.isIncomplete &&
                              account.isSelectedForLaunch
                            }
                            usesLaunchSelection={canLaunch}
                            canDelete={canDelete && account.isStored}
                            forgetsMetadataOnly={retainsVendorHome(
                              provider,
                              account,
                            )}
                            disabled={busy}
                            onRequest={(kind) =>
                              onRequest(account.id, kind, account.authKind)
                            }
                            onLaunch={() => onLaunch(account)}
                          />
                        )}
                      </td>
                    )}
                  </tr>
                  {pendingKind !== null && pending !== null && (
                    <tr
                      id={confirmRowId}
                      className="border-t border-border-subtle bg-surface-raised"
                    >
                      <td
                        colSpan={columnCount}
                        headers={labelId}
                        className="py-3 pr-4 pl-3"
                      >
                        <Confirmation
                          id={confirmId}
                          confirmDanger={pendingKind === 'delete'}
                          label={
                            pendingKind === 'switch'
                              ? canLaunch
                                ? `Confirm selection of ${accountDisplayName(account)} for app launch`
                                : `Confirm switch to ${accountDisplayName(account)}`
                              : retainsVendorHome(provider, account)
                                ? `Confirm forgetting ${accountDisplayName(account)}`
                                : `Confirm deletion of ${accountDisplayName(account)}`
                          }
                          confirmLabel={
                            pendingKind === 'switch'
                              ? canLaunch
                                ? `Confirm selection of ${accountDisplayName(account)} for app launch`
                                : `Confirm switch to ${accountDisplayName(account)}`
                              : retainsVendorHome(provider, account)
                                ? `Confirm forgetting ${accountDisplayName(account)}`
                                : `Confirm deletion of ${accountDisplayName(account)}`
                          }
                          cancelLabel={
                            pendingKind === 'switch'
                              ? canLaunch
                                ? 'Cancel launch selection'
                                : 'Cancel switch'
                              : retainsVendorHome(provider, account)
                                ? 'Cancel forgetting'
                                : 'Cancel deletion'
                          }
                          disabled={busy}
                          onCancel={onCancelPending}
                          onConfirm={onConfirmPending}
                        >
                          {pendingKind === 'switch' ? (
                            canLaunch ? (
                              <>
                                Select {accountDisplayName(account)} for{' '}
                                {provider.displayName} app launches? This
                                changes manager metadata only, affects only a
                                process launched by this application, and does
                                not rewrite the tool&apos;s configuration or
                                change already-running sessions.
                              </>
                            ) : (
                              <>
                                Switch {provider.displayName} to{' '}
                                {accountDisplayName(account)}? This rewrites the
                                live tool config, behind a restorable backup.{' '}
                                {provider.displayName} must not be running.
                              </>
                            )
                          ) : (
                            deleteConfirmation(provider, account)
                          )}
                        </Confirmation>
                      </td>
                    </tr>
                  )}
                </Fragment>
              )
            })}
          </tbody>
        </table>
      </div>
    </>
  )
}

function listingFor(
  listings: ProviderAccountList[],
  providerId: string,
): ProviderAccountList | undefined {
  return listings.find((listing) => listing.providerId === providerId)
}

function listingHasUnstored(listing: ProviderAccountList | undefined): boolean {
  return (
    listing !== undefined &&
    listing.accounts.some((account) => !account.isStored)
  )
}

function presentOrAbsent(
  value: string | null,
  absent: string,
): string | ReactElement {
  if (value === null || value.trim() === '') {
    return <span className="text-ink-muted">{absent}</span>
  }
  return value
}

function hasExpiry(account: Account): boolean {
  return account.expiresAt !== null && account.expiresAt.trim() !== ''
}

/**
 * Render an expiry for a person, not a log. Date and time sit on two
 * nowrap lines so the column is only as wide as the date. Unparseable
 * values are shown as the adapter produced them — they may not be
 * timestamps at all.
 */
function formatExpiry(value: string | null): ReactNode {
  if (value === null || value.trim() === '') {
    return <span className="text-ink-muted">Not established</span>
  }
  const parsed = Date.parse(value)
  if (Number.isNaN(parsed)) {
    return value
  }
  const date = new Date(parsed)
  const datePart = new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
  }).format(date)
  const timePart = new Intl.DateTimeFormat(undefined, {
    timeStyle: 'short',
  }).format(date)
  return (
    <time dateTime={value} title={value} className="expiry">
      <span>{datePart}</span>
      <span>{timePart}</span>
    </time>
  )
}

function accountRowClass(isActive: boolean): string {
  if (isActive) {
    return 'is-active border-t border-border-subtle'
  }
  return 'border-t border-border-subtle'
}

/**
 * Incomplete is a structural fact about the stored directory, not a
 * missing active-account probe. Say that first so a blank identity is
 * not the only clue. The visible label is the one word "Incomplete" so
 * the status cell stays on one line; the rest of the sentence is the
 * `title`, and the identity cell already says there is no usable
 * credential. `isActive: false` on every complete row is still not a
 * negative check — only say "Active" when at least one row is marked
 * active. The word "Active" is the state, not the colour.
 */
function statusCell(account: Account, activeKnown: boolean): ReactNode {
  if (account.isIncomplete) {
    const detail = 'Incomplete — sign-in never finished'
    return (
      <span className="chip chip-warn" title={detail}>
        Incomplete
      </span>
    )
  }
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5">
      {account.isSelectedForLaunch && (
        <span className="chip chip-accent">Selected for app launch</span>
      )}
      {!activeKnown ? (
        <span className="text-ink-muted">Not known</span>
      ) : account.isActive ? (
        <span className="chip">Active</span>
      ) : (
        <span className="text-ink-muted">—</span>
      )}
    </span>
  )
}

function deleteConfirmation(
  provider: ProviderDescriptor,
  account: Account,
): ReactNode {
  const name = accountDisplayName(account)
  if (retainsVendorHome(provider, account)) {
    return (
      <>
        Forget {name} from this application&apos;s metadata? The vendor-written
        isolated home and credential deliberately remain on disk. This does not
        sign out {provider.displayName} or destroy its credential.
      </>
    )
  }
  if (provider.id === 'gemini-cli') {
    return (
      <>
        Delete {name} from CredentialStore and forget its manager metadata?
        Already-running {provider.displayName} processes are unaffected.
      </>
    )
  }
  return (
    <>
      Forget this application&apos;s stored copy of {name}?{' '}
      {provider.displayName} is not signed out, and its own files are left
      untouched.
    </>
  )
}

/** Embed a filesystem path as a path, not as wrapping prose. */
function textWithPath(message: string, path: string | null): ReactNode {
  if (path === null || path === '' || !message.includes(path)) {
    return message
  }
  const pieces = message.split(path)
  return pieces.map((piece, index) => (
    <Fragment key={index}>
      {index > 0 && <code className="fs-path">{path}</code>}
      {piece}
    </Fragment>
  ))
}

function hasCapability(
  provider: ProviderDescriptor,
  capability: ProviderCapability,
): boolean {
  return provider.capabilities.includes(capability)
}

function retainsVendorHome(
  provider: ProviderDescriptor,
  account: Account,
): boolean {
  return (
    provider.id === 'grok-cli' ||
    (provider.id === 'gemini-cli' && account.authKind === 'oauth')
  )
}

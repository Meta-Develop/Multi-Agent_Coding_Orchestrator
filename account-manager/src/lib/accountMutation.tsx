import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import type { PendingKind } from '@/components/AccountActions'
import {
  activateAccount,
  addAccount,
  deleteAccount,
  launchProvider,
} from '@/lib/tauri'
import type { AuthKind, ProviderDescriptor } from '@/types'

export interface PendingConfirmation {
  providerId: string
  accountId: string
  kind: PendingKind
  authKind?: AuthKind
}

export interface Notice {
  tone: 'progress' | 'success' | 'failure'
  message: string
}

interface AccountMutationValue {
  busy: boolean
  notice: Notice | null
  pending: PendingConfirmation | null
  /** Bumped after a successful command so a mounted page re-fetches. */
  listingEpoch: number
  requestPending: (pending: PendingConfirmation) => void
  cancelPending: () => void
  runMutation: (
    kind: PendingKind | 'add',
    provider: ProviderDescriptor,
    accountId: string,
    accountName: string,
    authKind?: AuthKind,
  ) => Promise<boolean>
  runLaunch: (
    provider: ProviderDescriptor,
    accountName: string,
  ) => Promise<boolean>
}

const AccountMutationContext = createContext<AccountMutationValue | null>(null)

/**
 * Holds in-flight add/switch/delete across route changes. The Accounts
 * page unmounts when the sidebar is used; `add_account` can block for as
 * long as `codex login` takes in the launching terminal. That state has
 * to live here so a second sign-in cannot be started and so returning to
 * Accounts still shows the running operation. Unmounting is not
 * cancellation: this application cannot cancel a vendor login already
 * running in the terminal.
 */
export function AccountMutationProvider({ children }: { children: ReactNode }) {
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [pending, setPending] = useState<PendingConfirmation | null>(null)
  const [listingEpoch, setListingEpoch] = useState(0)
  const busyRef = useRef(false)

  const requestPending = useCallback((next: PendingConfirmation) => {
    if (busyRef.current) return
    setPending(next)
  }, [])

  const cancelPending = useCallback(() => {
    setPending(null)
  }, [])

  const runMutation = useCallback(
    async (
      kind: PendingKind | 'add',
      provider: ProviderDescriptor,
      accountId: string,
      accountName: string,
      authKind?: AuthKind,
    ): Promise<boolean> => {
      if (busyRef.current) {
        return false
      }
      busyRef.current = true
      setPending(null)
      setBusy(true)
      setNotice({
        tone: 'progress',
        message: progressMessage(
          kind,
          provider,
          accountId,
          accountName,
          authKind,
        ),
      })
      try {
        try {
          if (kind === 'add') {
            await addAccount(provider.id, accountId, authKind)
          } else if (kind === 'switch') {
            await activateAccount(provider.id, accountId)
          } else {
            await deleteAccount(provider.id, accountId)
          }
        } catch (cause: unknown) {
          setNotice({
            tone: 'failure',
            message: `${failureLead(kind, provider, accountId, accountName, authKind)} ${commandErrorMessage(cause)}`,
          })
          return false
        }
        setListingEpoch((epoch) => epoch + 1)
        setNotice({
          tone: 'success',
          message: successMessage(
            kind,
            provider,
            accountId,
            accountName,
            authKind,
          ),
        })
        return true
      } finally {
        busyRef.current = false
        setBusy(false)
      }
    },
    [],
  )

  const runLaunch = useCallback(
    async (
      provider: ProviderDescriptor,
      accountName: string,
    ): Promise<boolean> => {
      if (busyRef.current) {
        return false
      }
      busyRef.current = true
      setPending(null)
      setBusy(true)
      setNotice({
        tone: 'progress',
        message: `Launching ${provider.displayName} with ${accountName}, using the account selected for this app-owned process…`,
      })
      try {
        try {
          const process = await launchProvider(provider.id)
          setNotice({
            tone: 'success',
            message: `Launched an app-owned ${provider.displayName} child for ${process.accountId} (PID ${process.processId}). External launches and already-running sessions are unchanged.`,
          })
        } catch (cause: unknown) {
          setNotice({
            tone: 'failure',
            message: `Could not launch ${provider.displayName} for ${accountName}: ${commandErrorMessage(cause)}`,
          })
          return false
        }
        return true
      } finally {
        busyRef.current = false
        setBusy(false)
      }
    },
    [],
  )

  const value = useMemo<AccountMutationValue>(
    () => ({
      busy,
      notice,
      pending,
      listingEpoch,
      requestPending,
      cancelPending,
      runMutation,
      runLaunch,
    }),
    [
      busy,
      notice,
      pending,
      listingEpoch,
      requestPending,
      cancelPending,
      runMutation,
      runLaunch,
    ],
  )

  return (
    <AccountMutationContext.Provider value={value}>
      {children}
    </AccountMutationContext.Provider>
  )
}

export function useAccountMutation(): AccountMutationValue {
  const value = useContext(AccountMutationContext)
  if (value === null) {
    throw new Error(
      'useAccountMutation must be used within AccountMutationProvider',
    )
  }
  return value
}

/** Visible from every page so a running mutation is not an Accounts-only fact. */
export function MutationNotice() {
  const { notice } = useAccountMutation()
  if (notice === null) {
    return null
  }
  return (
    <p
      key={notice.message}
      role={notice.tone === 'failure' ? 'alert' : 'status'}
      className={noticeClass(notice.tone)}
    >
      {notice.message}
    </p>
  )
}

function noticeClass(tone: Notice['tone']): string {
  if (tone === 'failure') {
    return 'mb-4 rounded-md border border-border-subtle p-3 text-sm'
  }
  if (tone === 'progress') {
    return 'mb-4 rounded-md border border-border-subtle bg-surface-raised p-3 text-sm'
  }
  return 'mb-4 text-sm text-ink-muted'
}

function progressMessage(
  kind: PendingKind | 'add',
  provider: ProviderDescriptor,
  accountId: string,
  accountName: string,
  authKind?: AuthKind,
): string {
  if (kind === 'add') {
    if (provider.id === 'gemini-cli' && authKind === 'api-key') {
      return `Importing API key for ${accountId} from the native parent process into CredentialStore…`
    }
    if (provider.id === 'gemini-cli') {
      return `Signing in to ${provider.displayName} as ${accountId}. Finish Google sign-in in the browser; this window never takes a password. Leaving this page does not cancel it.`
    }
    if (provider.id === 'grok-cli') {
      return `Signing in to ${provider.displayName} as ${accountId}. The vendor window or terminal completes OAuth and will write a retained isolated home; leaving this page does not cancel it.`
    }
    return `Signing in to ${provider.displayName} as ${accountId}. The vendor window or terminal completes OAuth; this window will update when it finishes. Closing this window does not cancel that sign-in, and this application cannot cancel it either.`
  }
  if (kind === 'switch') {
    if (provider.capabilities.includes('launch-tool')) {
      return `Selecting ${accountName} for ${provider.displayName} app launches…`
    }
    return `Switching ${provider.displayName} to ${accountName}…`
  }
  if (retainsVendorHome(provider, authKind)) {
    return `Forgetting ${accountName} from this application's metadata. The vendor-written home and credential will remain on disk.`
  }
  if (provider.id === 'gemini-cli') {
    return `Deleting ${accountName} from CredentialStore. Already-running ${provider.displayName} processes are unaffected.`
  }
  return `Deleting this application's stored copy of ${accountName}…`
}

function successMessage(
  kind: PendingKind | 'add',
  provider: ProviderDescriptor,
  accountId: string,
  accountName: string,
  authKind?: AuthKind,
): string {
  if (kind === 'add') {
    if (provider.id === 'gemini-cli' && authKind === 'api-key') {
      return `Imported API key for ${accountId}.`
    }
    return `Signed in to ${provider.displayName} as ${accountId}.`
  }
  if (kind === 'switch') {
    if (provider.capabilities.includes('launch-tool')) {
      return `Selected ${accountName} for ${provider.displayName} app launches.`
    }
    return `Switched ${provider.displayName} to ${accountName}.`
  }
  if (retainsVendorHome(provider, authKind)) {
    return `Forgot ${accountName} from this application's metadata. Its vendor-written home and credential remain on disk.`
  }
  if (provider.id === 'gemini-cli') {
    return `Deleted ${accountName} from CredentialStore. Already-running ${provider.displayName} processes were not changed.`
  }
  return `Deleted this application's stored copy of ${accountName}.`
}

function failureLead(
  kind: PendingKind | 'add',
  provider: ProviderDescriptor,
  accountId: string,
  accountName: string,
  authKind?: AuthKind,
): string {
  if (kind === 'add') {
    if (provider.id === 'gemini-cli' && authKind === 'api-key') {
      return `Could not import API key for ${accountId}:`
    }
    return `Could not sign in to ${provider.displayName} as ${accountId}:`
  }
  if (kind === 'switch') {
    if (provider.capabilities.includes('launch-tool')) {
      return `Could not select ${accountName} for ${provider.displayName} app launches:`
    }
    return `Could not switch ${provider.displayName} to ${accountName}:`
  }
  if (retainsVendorHome(provider, authKind)) {
    return `Could not forget ${accountName} from this application's metadata:`
  }
  if (provider.id === 'gemini-cli') {
    return `Could not delete ${accountName} from CredentialStore:`
  }
  return `Could not delete ${accountName}:`
}

function retainsVendorHome(
  provider: ProviderDescriptor,
  authKind?: AuthKind,
): boolean {
  return (
    provider.id === 'grok-cli' ||
    (provider.id === 'gemini-cli' && authKind === 'oauth')
  )
}

function commandErrorMessage(cause: unknown): string {
  if (typeof cause === 'string' && cause.trim() !== '') {
    return cause
  }
  if (cause instanceof Error && cause.message.trim() !== '') {
    return cause.message
  }
  return 'The command failed without an error message.'
}

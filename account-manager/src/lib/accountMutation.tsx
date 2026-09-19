import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import type { PendingKind } from '@/components/AccountActions'
import {
  OAUTH_LOGIN_POLL_INTERVAL_MS,
  geminiOAuthCancelledMessage,
  geminiOAuthFailedMessage,
  geminiOAuthPollErrorMessage,
  geminiOAuthProgressMessage,
  geminiOAuthReadyMessage,
  geminiOAuthUnknownMessage,
  isActiveLoginState,
  newIdempotencyKey,
  shouldStopAutomaticPoll,
  statusMatchesSession,
} from '@/lib/oauthLoginLifecycle'
import {
  activateAccount,
  addAccount,
  deleteAccount,
  launchProvider,
  loginCancel,
  loginStart,
  loginStatus,
} from '@/lib/tauri'
import type {
  AuthKind,
  LoginState,
  LoginStatus,
  ProviderDescriptor,
} from '@/types'

export interface GeminiOAuthLoginSession {
  providerId: string
  accountId: string
  displayName: string
  handle: string
  binding: LoginStatus['binding']
  idempotencyKey: string
  cancelRequested: boolean
  pollStopped: boolean
  lastState: LoginState
}

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
  geminiOAuth: GeminiOAuthLoginSession | null
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
  cancelGeminiOAuthLogin: () => void
  checkGeminiOAuthLoginStatus: () => void
}

const AccountMutationContext = createContext<AccountMutationValue | null>(null)

const GEMINI_PROVIDER_ID = 'gemini-cli'

/**
 * Holds in-flight add/switch/delete across route changes. The Accounts
 * page unmounts when the sidebar is used; vendor sign-in can block for a
 * long time. Gemini OAuth uses the explicit core login lifecycle with
 * bounded status polling instead of blocking `add_account`.
 */
export function AccountMutationProvider({ children }: { children: ReactNode }) {
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [pending, setPending] = useState<PendingConfirmation | null>(null)
  const [geminiOAuth, setGeminiOAuth] =
    useState<GeminiOAuthLoginSession | null>(null)
  const [listingEpoch, setListingEpoch] = useState(0)
  const busyRef = useRef(false)
  const geminiOAuthRef = useRef<GeminiOAuthLoginSession | null>(null)
  const idempotencyKeysRef = useRef<Map<string, string>>(new Map())
  const pollInFlightRef = useRef(false)
  const pollTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const pollGenerationRef = useRef(0)

  geminiOAuthRef.current = geminiOAuth

  const clearPollTimer = useCallback(() => {
    if (pollTimerRef.current !== null) {
      clearTimeout(pollTimerRef.current)
      pollTimerRef.current = null
    }
  }, [])

  const clearIdempotencyKey = useCallback(
    (providerId: string, accountId: string) => {
      idempotencyKeysRef.current.delete(`${providerId}:${accountId}`)
    },
    [],
  )

  const finishGeminiOAuthSession = useCallback(
    (providerId: string, accountId: string) => {
      clearPollTimer()
      pollGenerationRef.current += 1
      clearIdempotencyKey(providerId, accountId)
      setGeminiOAuth(null)
      busyRef.current = false
      setBusy(false)
    },
    [clearIdempotencyKey, clearPollTimer],
  )

  const applyGeminiOAuthStatus = useCallback(
    (status: LoginStatus, session: GeminiOAuthLoginSession) => {
      if (!statusMatchesSession(status, session.handle, session.binding)) {
        return
      }

      const nextSession: GeminiOAuthLoginSession = {
        ...session,
        lastState: status.state,
      }
      setGeminiOAuth(nextSession)

      if (status.state === 'ready') {
        setListingEpoch((epoch) => epoch + 1)
        setNotice({
          tone: 'success',
          message: geminiOAuthReadyMessage(
            session.accountId,
            session.displayName,
          ),
        })
        finishGeminiOAuthSession(session.providerId, session.accountId)
        return
      }

      if (status.state === 'cancelled') {
        setNotice({
          tone: 'success',
          message: geminiOAuthCancelledMessage(
            session.accountId,
            session.displayName,
          ),
        })
        finishGeminiOAuthSession(session.providerId, session.accountId)
        return
      }

      if (status.state === 'failed') {
        setNotice({
          tone: 'failure',
          message: geminiOAuthFailedMessage(
            session.accountId,
            session.displayName,
            status.failureReason,
          ),
        })
        finishGeminiOAuthSession(session.providerId, session.accountId)
        return
      }

      if (status.state === 'unknown') {
        setGeminiOAuth({ ...nextSession, pollStopped: true })
        busyRef.current = false
        setBusy(false)
        setNotice({
          tone: 'failure',
          message: geminiOAuthUnknownMessage(
            session.accountId,
            session.displayName,
          ),
        })
        return
      }

      setNotice({
        tone: 'progress',
        message: geminiOAuthProgressMessage(
          session.accountId,
          session.displayName,
          status.state,
          session.cancelRequested,
        ),
      })
    },
    [finishGeminiOAuthSession],
  )

  const runPollTick = useCallback(
    async (generation: number) => {
      if (generation !== pollGenerationRef.current) {
        return
      }
      const session = geminiOAuthRef.current
      if (session === null || session.pollStopped) {
        return
      }
      if (shouldStopAutomaticPoll(session.lastState)) {
        return
      }
      if (pollInFlightRef.current) {
        pollTimerRef.current = setTimeout(() => {
          void runPollTick(generation)
        }, OAUTH_LOGIN_POLL_INTERVAL_MS)
        return
      }
      pollInFlightRef.current = true
      try {
        const status = await loginStatus({
          handle: session.handle,
          binding: session.binding,
        })
        if (generation !== pollGenerationRef.current) {
          return
        }
        const current = geminiOAuthRef.current
        if (current === null) {
          return
        }
        applyGeminiOAuthStatus(status, current)
        if (
          generation === pollGenerationRef.current &&
          geminiOAuthRef.current !== null &&
          !geminiOAuthRef.current.pollStopped &&
          isActiveLoginState(geminiOAuthRef.current.lastState)
        ) {
          pollTimerRef.current = setTimeout(() => {
            void runPollTick(generation)
          }, OAUTH_LOGIN_POLL_INTERVAL_MS)
        }
      } catch {
        if (generation !== pollGenerationRef.current) {
          return
        }
        const current = geminiOAuthRef.current
        if (current === null) {
          return
        }
        setGeminiOAuth({ ...current, pollStopped: true })
        busyRef.current = false
        setBusy(false)
        setNotice({
          tone: 'failure',
          message: geminiOAuthPollErrorMessage(
            current.accountId,
            current.displayName,
          ),
        })
      } finally {
        pollInFlightRef.current = false
      }
    },
    [applyGeminiOAuthStatus],
  )

  useEffect(() => {
    const session = geminiOAuth
    if (session === null || session.pollStopped) {
      clearPollTimer()
      return
    }
    if (shouldStopAutomaticPoll(session.lastState)) {
      clearPollTimer()
      return
    }
    const generation = pollGenerationRef.current
    pollTimerRef.current = setTimeout(() => {
      void runPollTick(generation)
    }, OAUTH_LOGIN_POLL_INTERVAL_MS)
    return () => {
      clearPollTimer()
    }
  }, [
    geminiOAuth?.handle,
    geminiOAuth?.binding.accountIncarnation,
    geminiOAuth?.pollStopped,
    geminiOAuth?.lastState,
    runPollTick,
    clearPollTimer,
    geminiOAuth,
  ])

  useEffect(() => {
    return () => {
      pollGenerationRef.current += 1
      clearPollTimer()
    }
  }, [clearPollTimer])

  const startGeminiOAuthLogin = useCallback(
    async (
      provider: ProviderDescriptor,
      accountId: string,
    ): Promise<boolean> => {
      const existing = geminiOAuthRef.current
      if (existing !== null && isActiveLoginState(existing.lastState)) {
        return false
      }
      if (existing !== null) {
        clearPollTimer()
        pollGenerationRef.current += 1
        setGeminiOAuth(null)
      }

      const idempotencyMapKey = `${provider.id}:${accountId}`
      let idempotencyKey = idempotencyKeysRef.current.get(idempotencyMapKey)
      if (idempotencyKey === undefined) {
        idempotencyKey = newIdempotencyKey()
        idempotencyKeysRef.current.set(idempotencyMapKey, idempotencyKey)
      }

      busyRef.current = true
      setPending(null)
      setBusy(true)
      pollGenerationRef.current += 1
      clearPollTimer()
      setNotice({
        tone: 'progress',
        message: geminiOAuthProgressMessage(
          accountId,
          provider.displayName,
          'waiting-for-user',
          false,
        ),
      })

      try {
        const status = await loginStart({
          providerId: provider.id,
          accountId,
          label: accountId,
          authKind: 'oauth',
          idempotencyKey,
        })
        const session: GeminiOAuthLoginSession = {
          providerId: provider.id,
          accountId,
          displayName: provider.displayName,
          handle: status.handle,
          binding: status.binding,
          idempotencyKey,
          cancelRequested: false,
          pollStopped: false,
          lastState: status.state,
        }
        setGeminiOAuth(session)
        applyGeminiOAuthStatus(status, session)
        return status.state === 'ready'
      } catch (cause: unknown) {
        clearIdempotencyKey(provider.id, accountId)
        setNotice({
          tone: 'failure',
          message: geminiOAuthFailedMessage(
            accountId,
            provider.displayName,
            commandErrorMessage(cause),
          ),
        })
        busyRef.current = false
        setBusy(false)
        return false
      }
    },
    [applyGeminiOAuthStatus, clearIdempotencyKey, clearPollTimer],
  )

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
      if (
        kind === 'add' &&
        provider.id === GEMINI_PROVIDER_ID &&
        authKind === 'oauth'
      ) {
        return startGeminiOAuthLogin(provider, accountId)
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
    [startGeminiOAuthLogin],
  )

  const cancelGeminiOAuthLogin = useCallback(() => {
    const session = geminiOAuthRef.current
    if (session === null) {
      return
    }
    setGeminiOAuth({ ...session, cancelRequested: true })
    setNotice({
      tone: 'progress',
      message: geminiOAuthProgressMessage(
        session.accountId,
        session.displayName,
        session.lastState,
        true,
      ),
    })
    void loginCancel({
      handle: session.handle,
      binding: session.binding,
    })
      .then((status) => {
        const current = geminiOAuthRef.current
        if (current === null) {
          return
        }
        applyGeminiOAuthStatus(status, current)
      })
      .catch(() => {
        const current = geminiOAuthRef.current
        if (current === null) {
          return
        }
        setGeminiOAuth({ ...current, pollStopped: true })
        busyRef.current = false
        setBusy(false)
        setNotice({
          tone: 'failure',
          message: geminiOAuthPollErrorMessage(
            current.accountId,
            current.displayName,
          ),
        })
      })
  }, [applyGeminiOAuthStatus])

  const checkGeminiOAuthLoginStatus = useCallback(() => {
    const session = geminiOAuthRef.current
    if (session === null) {
      return
    }
    void loginStatus({
      handle: session.handle,
      binding: session.binding,
    })
      .then((status) => {
        const current = geminiOAuthRef.current
        if (current === null) {
          return
        }
        const resumed: GeminiOAuthLoginSession = {
          ...current,
          pollStopped: false,
        }
        setGeminiOAuth(resumed)
        applyGeminiOAuthStatus(status, resumed)
      })
      .catch(() => {
        const current = geminiOAuthRef.current
        if (current === null) {
          return
        }
        setNotice({
          tone: 'failure',
          message: geminiOAuthPollErrorMessage(
            current.accountId,
            current.displayName,
          ),
        })
      })
  }, [applyGeminiOAuthStatus])

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
      geminiOAuth,
      listingEpoch,
      requestPending,
      cancelPending,
      runMutation,
      runLaunch,
      cancelGeminiOAuthLogin,
      checkGeminiOAuthLoginStatus,
    }),
    [
      busy,
      notice,
      pending,
      geminiOAuth,
      listingEpoch,
      requestPending,
      cancelPending,
      runMutation,
      runLaunch,
      cancelGeminiOAuthLogin,
      checkGeminiOAuthLoginStatus,
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
  const {
    notice,
    geminiOAuth,
    cancelGeminiOAuthLogin,
    checkGeminiOAuthLoginStatus,
  } = useAccountMutation()
  if (notice === null) {
    return null
  }
  const showOAuthActions =
    geminiOAuth !== null &&
    (isActiveLoginState(geminiOAuth.lastState) ||
      geminiOAuth.pollStopped ||
      geminiOAuth.lastState === 'unknown')
  return (
    <div className="mb-4">
      <p
        key={notice.message}
        role={notice.tone === 'failure' ? 'alert' : 'status'}
        className={noticeClass(notice.tone)}
      >
        {notice.message}
      </p>
      {showOAuthActions && (
        <div className="mt-2 flex flex-wrap gap-2">
          {isActiveLoginState(geminiOAuth.lastState) &&
            !geminiOAuth.cancelRequested && (
              <button
                type="button"
                className="btn"
                onClick={cancelGeminiOAuthLogin}
              >
                Cancel sign-in
              </button>
            )}
          {(geminiOAuth.pollStopped || geminiOAuth.lastState === 'unknown') && (
            <button
              type="button"
              className="btn btn-primary"
              onClick={checkGeminiOAuthLoginStatus}
            >
              Check status
            </button>
          )}
        </div>
      )}
    </div>
  )
}

function noticeClass(tone: Notice['tone']): string {
  if (tone === 'failure') {
    return 'rounded-md border border-border-subtle p-3 text-sm'
  }
  if (tone === 'progress') {
    return 'rounded-md border border-border-subtle bg-surface-raised p-3 text-sm'
  }
  return 'text-sm text-ink-muted'
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

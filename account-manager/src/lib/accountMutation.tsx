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
  oauthCancelledMessage,
  oauthFailedMessage,
  oauthPollErrorMessage,
  oauthProgressMessage,
  oauthReadyMessage,
  oauthUnknownMessage,
  hasLiveAuthorization,
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
  loginOpenAuthorization,
  loginStart,
  loginStatus,
} from '@/lib/tauri'
import type {
  AuthKind,
  LoginState,
  LoginStatus,
  ProviderDescriptor,
} from '@/types'

export interface OAuthLoginSession {
  providerId: string
  accountId: string
  displayName: string
  handle: string
  binding: LoginStatus['binding']
  idempotencyKey: string
  cancelRequested: boolean
  pollStopped: boolean
  lastState: LoginState
  authorizationAvailable: boolean
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
  oauth: OAuthLoginSession | null
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
  cancelOAuthLogin: () => void
  checkOAuthLoginStatus: () => void
  openOAuthAuthorization: () => void
  openingAuthorization: boolean
}

const AccountMutationContext = createContext<AccountMutationValue | null>(null)

/**
 * Holds in-flight add/switch/delete across route changes. The Accounts
 * page unmounts when the sidebar is used; vendor sign-in can block for a
 * long time. OAuth uses the explicit core login lifecycle with
 * bounded status polling instead of blocking `add_account`.
 */
export function AccountMutationProvider({ children }: { children: ReactNode }) {
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [pending, setPending] = useState<PendingConfirmation | null>(null)
  const [oauth, setOAuth] = useState<OAuthLoginSession | null>(null)
  const [listingEpoch, setListingEpoch] = useState(0)
  const [openingAuthorization, setOpeningAuthorization] = useState(false)
  const openingAuthorizationRef = useRef(false)
  const busyRef = useRef(false)
  const oauthRef = useRef<OAuthLoginSession | null>(null)
  const idempotencyKeysRef = useRef<Map<string, string>>(new Map())
  const pollInFlightRef = useRef(false)
  const pollTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const pollGenerationRef = useRef(0)

  oauthRef.current = oauth

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

  const finishOAuthSession = useCallback(
    (providerId: string, accountId: string) => {
      clearPollTimer()
      pollGenerationRef.current += 1
      clearIdempotencyKey(providerId, accountId)
      setOAuth(null)
      busyRef.current = false
      setBusy(false)
    },
    [clearIdempotencyKey, clearPollTimer],
  )

  const applyOAuthStatus = useCallback(
    (status: LoginStatus, session: OAuthLoginSession) => {
      if (!statusMatchesSession(status, session.handle, session.binding)) {
        return
      }

      const nextSession: OAuthLoginSession = {
        ...session,
        lastState: status.state,
        authorizationAvailable:
          !session.cancelRequested && hasLiveAuthorization(status),
      }
      setOAuth(nextSession)

      if (status.state === 'ready') {
        setListingEpoch((epoch) => epoch + 1)
        setNotice({
          tone: 'success',
          message: oauthReadyMessage(session.accountId, session.displayName),
        })
        finishOAuthSession(session.providerId, session.accountId)
        return
      }

      if (status.state === 'cancelled') {
        setNotice({
          tone: 'success',
          message: oauthCancelledMessage(
            session.accountId,
            session.displayName,
          ),
        })
        finishOAuthSession(session.providerId, session.accountId)
        return
      }

      if (status.state === 'failed') {
        setNotice({
          tone: 'failure',
          message: oauthFailedMessage(
            session.accountId,
            session.displayName,
            status.failureReason,
          ),
        })
        finishOAuthSession(session.providerId, session.accountId)
        return
      }

      if (status.state === 'unknown') {
        setOAuth({ ...nextSession, pollStopped: true })
        busyRef.current = false
        setBusy(false)
        setNotice({
          tone: 'failure',
          message: oauthUnknownMessage(session.accountId, session.displayName),
        })
        return
      }

      setNotice({
        tone: 'progress',
        message: oauthProgressMessage(
          session.accountId,
          session.displayName,
          status.state,
          session.cancelRequested,
        ),
      })
    },
    [finishOAuthSession],
  )

  const runPollTick = useCallback(
    async (generation: number) => {
      if (generation !== pollGenerationRef.current) {
        return
      }
      const session = oauthRef.current
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
        const current = oauthRef.current
        if (current === null) {
          return
        }
        applyOAuthStatus(status, current)
        if (
          generation === pollGenerationRef.current &&
          oauthRef.current !== null &&
          !oauthRef.current.pollStopped &&
          isActiveLoginState(oauthRef.current.lastState)
        ) {
          pollTimerRef.current = setTimeout(() => {
            void runPollTick(generation)
          }, OAUTH_LOGIN_POLL_INTERVAL_MS)
        }
      } catch {
        if (generation !== pollGenerationRef.current) {
          return
        }
        const current = oauthRef.current
        if (current === null) {
          return
        }
        setOAuth({
          ...current,
          pollStopped: true,
          authorizationAvailable: false,
        })
        busyRef.current = false
        setBusy(false)
        setNotice({
          tone: 'failure',
          message: oauthPollErrorMessage(
            current.accountId,
            current.displayName,
          ),
        })
      } finally {
        pollInFlightRef.current = false
      }
    },
    [applyOAuthStatus],
  )

  useEffect(() => {
    const session = oauth
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
    oauth?.handle,
    oauth?.binding.accountIncarnation,
    oauth?.pollStopped,
    oauth?.lastState,
    runPollTick,
    clearPollTimer,
    oauth,
  ])

  useEffect(() => {
    return () => {
      pollGenerationRef.current += 1
      clearPollTimer()
    }
  }, [clearPollTimer])

  const startOAuthLogin = useCallback(
    async (
      provider: ProviderDescriptor,
      accountId: string,
    ): Promise<boolean> => {
      const existing = oauthRef.current
      if (existing !== null && isActiveLoginState(existing.lastState)) {
        return false
      }
      if (existing !== null) {
        clearPollTimer()
        pollGenerationRef.current += 1
        setOAuth(null)
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
        message: oauthProgressMessage(
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
        if (
          status.binding.providerId !== provider.id ||
          status.binding.accountId !== accountId ||
          status.binding.accountIncarnation.trim() === '' ||
          status.handle.trim() === ''
        ) {
          throw new Error(
            'The login response did not match the requested account.',
          )
        }
        const session: OAuthLoginSession = {
          providerId: provider.id,
          accountId,
          displayName: provider.displayName,
          handle: status.handle,
          binding: status.binding,
          idempotencyKey,
          cancelRequested: false,
          pollStopped: false,
          lastState: status.state,
          authorizationAvailable: hasLiveAuthorization(status),
        }
        setOAuth(session)
        applyOAuthStatus(status, session)
        return status.state === 'ready'
      } catch (cause: unknown) {
        clearIdempotencyKey(provider.id, accountId)
        setNotice({
          tone: 'failure',
          message: oauthFailedMessage(
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
    [applyOAuthStatus, clearIdempotencyKey, clearPollTimer],
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
        (authKind === 'oauth' ||
          (authKind === undefined && provider.authKinds.includes('oauth')))
      ) {
        return startOAuthLogin(provider, accountId)
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
    [startOAuthLogin],
  )

  const cancelOAuthLogin = useCallback(() => {
    const session = oauthRef.current
    if (session === null) {
      return
    }
    const generation = pollGenerationRef.current
    const cancelling = {
      ...session,
      cancelRequested: true,
      authorizationAvailable: false,
    }
    oauthRef.current = cancelling
    setOAuth(cancelling)
    setNotice({
      tone: 'progress',
      message: oauthProgressMessage(
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
        if (generation !== pollGenerationRef.current) {
          return
        }
        const current = oauthRef.current
        if (current === null) {
          return
        }
        applyOAuthStatus(status, current)
      })
      .catch(() => {
        if (generation !== pollGenerationRef.current) {
          return
        }
        const current = oauthRef.current
        if (current === null) {
          return
        }
        setOAuth({
          ...current,
          pollStopped: true,
          authorizationAvailable: false,
        })
        busyRef.current = false
        setBusy(false)
        setNotice({
          tone: 'failure',
          message: oauthPollErrorMessage(
            current.accountId,
            current.displayName,
          ),
        })
      })
  }, [applyOAuthStatus])

  const checkOAuthLoginStatus = useCallback(() => {
    const session = oauthRef.current
    if (session === null) {
      return
    }
    const generation = pollGenerationRef.current
    void loginStatus({
      handle: session.handle,
      binding: session.binding,
    })
      .then((status) => {
        if (generation !== pollGenerationRef.current) {
          return
        }
        const current = oauthRef.current
        if (
          current === null ||
          !statusMatchesSession(status, current.handle, current.binding)
        ) {
          return
        }
        const resumed: OAuthLoginSession = {
          ...current,
          pollStopped: false,
        }
        setOAuth(resumed)
        applyOAuthStatus(status, resumed)
      })
      .catch(() => {
        if (generation !== pollGenerationRef.current) {
          return
        }
        const current = oauthRef.current
        if (current === null) {
          return
        }
        setNotice({
          tone: 'failure',
          message: oauthPollErrorMessage(
            current.accountId,
            current.displayName,
          ),
        })
      })
  }, [applyOAuthStatus])

  const openOAuthAuthorization = useCallback(() => {
    const session = oauthRef.current
    if (
      session === null ||
      session.cancelRequested ||
      !session.authorizationAvailable ||
      !isActiveLoginState(session.lastState) ||
      openingAuthorizationRef.current
    ) {
      return
    }
    const generation = pollGenerationRef.current
    openingAuthorizationRef.current = true
    setOpeningAuthorization(true)
    void loginOpenAuthorization({
      handle: session.handle,
      binding: session.binding,
    })
      .then(() => {
        if (generation !== pollGenerationRef.current) return
        const current = oauthRef.current
        if (
          current === null ||
          current.cancelRequested ||
          !isActiveLoginState(current.lastState)
        )
          return
        setNotice({
          tone: 'progress',
          message: `Opened ${current.displayName} sign-in in your browser. Complete the provider's sign-in there; this application is waiting for its login result.`,
        })
      })
      .catch(() => {
        if (generation !== pollGenerationRef.current) return
        const current = oauthRef.current
        if (
          current === null ||
          current.cancelRequested ||
          !isActiveLoginState(current.lastState)
        )
          return
        setOAuth({
          ...current,
          authorizationAvailable: false,
          pollStopped: true,
        })
        clearPollTimer()
        setNotice({
          tone: 'failure',
          message: `Could not open current sign-in instructions for ${current.displayName}. Use Check status to retrieve the current login action.`,
        })
      })
      .finally(() => {
        openingAuthorizationRef.current = false
        setOpeningAuthorization(false)
      })
  }, [clearPollTimer])

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
      oauth,
      listingEpoch,
      requestPending,
      cancelPending,
      runMutation,
      runLaunch,
      cancelOAuthLogin,
      checkOAuthLoginStatus,
      openOAuthAuthorization,
      openingAuthorization,
    }),
    [
      busy,
      notice,
      pending,
      oauth,
      listingEpoch,
      requestPending,
      cancelPending,
      runMutation,
      runLaunch,
      cancelOAuthLogin,
      checkOAuthLoginStatus,
      openOAuthAuthorization,
      openingAuthorization,
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
    oauth,
    cancelOAuthLogin,
    checkOAuthLoginStatus,
    openOAuthAuthorization,
    openingAuthorization,
  } = useAccountMutation()
  if (notice === null) {
    return null
  }
  const showOAuthActions =
    oauth !== null &&
    (isActiveLoginState(oauth.lastState) ||
      oauth.pollStopped ||
      oauth.lastState === 'unknown')
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
          {isActiveLoginState(oauth.lastState) &&
            !oauth.cancelRequested &&
            oauth.authorizationAvailable && (
              <button
                type="button"
                className="btn btn-primary"
                disabled={openingAuthorization}
                onClick={openOAuthAuthorization}
              >
                Open {oauth.displayName} sign-in
              </button>
            )}
          {isActiveLoginState(oauth.lastState) && !oauth.cancelRequested && (
            <button type="button" className="btn" onClick={cancelOAuthLogin}>
              Cancel sign-in
            </button>
          )}
          {(oauth.pollStopped || oauth.lastState === 'unknown') && (
            <button
              type="button"
              className="btn btn-primary"
              onClick={checkOAuthLoginStatus}
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

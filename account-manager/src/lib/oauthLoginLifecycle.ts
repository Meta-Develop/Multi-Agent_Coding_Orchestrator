import type { LoginAccountBinding, LoginState, LoginStatus } from '@/types'

/** Bounded poll interval while a login handle is actively tracked. */
export const OAUTH_LOGIN_POLL_INTERVAL_MS = 1500

export function bindingsEqual(
  a: LoginAccountBinding,
  b: LoginAccountBinding,
): boolean {
  return (
    a.providerId === b.providerId &&
    a.accountId === b.accountId &&
    a.accountIncarnation === b.accountIncarnation
  )
}

/** Ignore poll/cancel responses that do not match the session being tracked. */
export function statusMatchesSession(
  status: LoginStatus,
  handle: string,
  binding: LoginAccountBinding,
): boolean {
  return status.handle === handle && bindingsEqual(status.binding, binding)
}

export function isActiveLoginState(state: LoginState): boolean {
  return state === 'waiting-for-user' || state === 'in-progress'
}

/** Only availability is kept in React state; native code validates and opens the URL. */
export function hasLiveAuthorization(
  status: LoginStatus,
  now = Date.now(),
): boolean {
  const authorization = status.authorization
  return (
    isActiveLoginState(status.state) &&
    authorization !== undefined &&
    authorization.authorizationUrl.trim() !== '' &&
    (authorization.expiresAtUnixMs === undefined ||
      authorization.expiresAtUnixMs > now)
  )
}

/** States that stop automatic polling (unknown still allows explicit check). */
export function shouldStopAutomaticPoll(state: LoginState): boolean {
  return !isActiveLoginState(state)
}

export function newIdempotencyKey(): string {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) {
    return crypto.randomUUID()
  }
  return `login-${Date.now()}-${Math.random().toString(36).slice(2)}`
}

export function oauthProgressMessage(
  accountId: string,
  displayName: string,
  state: LoginState,
  cancelRequested: boolean,
): string {
  if (cancelRequested && isActiveLoginState(state)) {
    return `Cancelling sign-in to ${displayName} as ${accountId}. Waiting for the login flow to settle…`
  }
  if (state === 'waiting-for-user') {
    return `Signing in to ${displayName} as ${accountId}. Complete the provider's sign-in when its authorization instructions are available. This window never takes a password or token. Leaving this page does not cancel sign-in.`
  }
  if (state === 'in-progress') {
    return `Completing sign-in to ${displayName} as ${accountId}. This application is tracking the provider's login; waiting for completion does not prove account or model access.`
  }
  return `Sign-in to ${displayName} as ${accountId} is still in progress…`
}

export function oauthPollErrorMessage(
  accountId: string,
  displayName: string,
): string {
  return `Could not confirm sign-in progress for ${displayName} as ${accountId}. The provider's login may still be running. Use Check status when you are ready; this application will not retry automatically.`
}

export function oauthUnknownMessage(
  accountId: string,
  displayName: string,
): string {
  return `Sign-in outcome for ${displayName} as ${accountId} is unknown. A pending account may remain. Use Check status; starting again with the same nickname may be refused.`
}

export function oauthReadyMessage(
  accountId: string,
  displayName: string,
): string {
  return `Added ${accountId} to ${displayName}. Refresh the list below and select an account yourself if you want app-owned launches; nothing was activated automatically. Model access is not established by this login status.`
}

export function oauthCancelledMessage(
  accountId: string,
  displayName: string,
): string {
  return `Sign-in to ${displayName} as ${accountId} was cancelled.`
}

export function oauthFailedMessage(
  accountId: string,
  displayName: string,
  failureReason: string | undefined,
): string {
  const detail =
    failureReason !== undefined && failureReason.trim() !== ''
      ? failureReason
      : 'The login failed without an error message.'
  return `Could not sign in to ${displayName} as ${accountId}: ${detail}`
}

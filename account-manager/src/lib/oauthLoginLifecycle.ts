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

export function geminiOAuthProgressMessage(
  accountId: string,
  displayName: string,
  state: LoginState,
  cancelRequested: boolean,
): string {
  if (cancelRequested && isActiveLoginState(state)) {
    return `Cancelling sign-in to ${displayName} as ${accountId}. Waiting for the login flow to settle…`
  }
  if (state === 'waiting-for-user') {
    return `Signing in to ${displayName} as ${accountId}. Finish Google sign-in in the browser you open; this window never takes a password and does not control that browser. Leaving this page does not cancel sign-in.`
  }
  if (state === 'in-progress') {
    return `Completing sign-in to ${displayName} as ${accountId}. The browser stays under your control; this application only tracks progress here.`
  }
  return `Sign-in to ${displayName} as ${accountId} is still in progress…`
}

export function geminiOAuthPollErrorMessage(
  accountId: string,
  displayName: string,
): string {
  return `Could not confirm sign-in progress for ${displayName} as ${accountId}. The login may still be running in your browser. Use Check status when you are ready; this application will not retry automatically.`
}

export function geminiOAuthUnknownMessage(
  accountId: string,
  displayName: string,
): string {
  return `Sign-in outcome for ${displayName} as ${accountId} is unknown. The account may or may not have been added. Check status or start again with the same nickname if you still need to recover a pending sign-in.`
}

export function geminiOAuthReadyMessage(
  accountId: string,
  displayName: string,
): string {
  return `Added ${accountId} to ${displayName}. Refresh the list below and select an account yourself if you want app-owned launches; nothing was activated automatically.`
}

export function geminiOAuthCancelledMessage(
  accountId: string,
  displayName: string,
): string {
  return `Sign-in to ${displayName} as ${accountId} was cancelled.`
}

export function geminiOAuthFailedMessage(
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

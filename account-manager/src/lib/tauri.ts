import { invoke } from '@tauri-apps/api/core'
import type {
  AccountObserveRequest,
  AccountObserveResult,
  AuthKind,
  LaunchedProcess,
  LaunchOperationStatus,
  LoginAccountBinding,
  LoginStatus,
  ProviderAccountList,
  ProviderDescriptor,
  ProviderQuotaList,
  RelayStatus,
  RouteRule,
  SelectedAccountBinding,
} from '@/types'

/**
 * Typed wrappers around the Tauri command surface.
 *
 * Keep this file as the single place the front end reaches into Rust so the
 * command names exist in exactly one location.
 */

export function listProviders(): Promise<ProviderDescriptor[]> {
  return invoke<ProviderDescriptor[]>('list_providers')
}

export function listAccounts(
  providerId?: string,
): Promise<ProviderAccountList[]> {
  return invoke<ProviderAccountList[]>('list_accounts', {
    providerId: providerId ?? null,
  })
}

export function addAccount(
  providerId: string,
  accountId: string,
  authKind?: AuthKind,
): Promise<void> {
  return invoke<void>(
    'add_account',
    authKind === undefined
      ? { providerId, accountId }
      : { providerId, accountId, authKind },
  )
}

export function activateAccount(
  providerId: string,
  accountId: string,
): Promise<void> {
  return invoke<void>('activate_account', { providerId, accountId })
}

export function deleteAccount(
  providerId: string,
  accountId: string,
): Promise<void> {
  return invoke<void>('delete_account', { providerId, accountId })
}

/** Read the authority's current public selection tuple; never selects or resolves a secret. */
export function selectedAccountBinding(
  providerId: string,
): Promise<SelectedAccountBinding | null> {
  return invoke<SelectedAccountBinding | null>('selected_account_binding', {
    providerId,
  })
}

/** Observes only the account named by `request.binding`; never auto-selects. */
export function observeAccount(
  request: AccountObserveRequest,
): Promise<AccountObserveResult> {
  return invoke<AccountObserveResult>('observe_account', { request })
}

/**
 * Launches only the account already selected in Rust-owned metadata. Account
 * ids, programs, arguments, environment names, paths, and secret values are
 * deliberately absent from this IPC boundary.
 */
export function launchProvider(providerId: string): Promise<LaunchedProcess> {
  return invoke<LaunchedProcess>('launch_provider', { providerId })
}

/** Queries only a handle retained by this desktop process. */
export function launchStatus(handle: string): Promise<LaunchOperationStatus> {
  return invoke<LaunchOperationStatus>('launch_status', { handle })
}

/** A cancellation request is not confirmation of child exit. */
export function launchCancel(handle: string): Promise<LaunchOperationStatus> {
  return invoke<LaunchOperationStatus>('launch_cancel', { handle })
}

export function listQuota(): Promise<ProviderQuotaList[]> {
  return invoke<ProviderQuotaList[]>('list_quota')
}

export function listRouteRules(): Promise<RouteRule[]> {
  return invoke<RouteRule[]>('list_route_rules')
}

/** Atomically replaces the complete ordered routing-rule list. */
export function replaceRouteRules(rules: RouteRule[]): Promise<void> {
  return invoke<void>('replace_route_rules', { rules })
}

export function relayStatus(): Promise<RelayStatus> {
  return invoke<RelayStatus>('relay_status')
}

/** Starts only the Rust core's safe default loopback configuration. */
export function startRelay(): Promise<RelayStatus> {
  return invoke<RelayStatus>('start_relay')
}

export function stopRelay(): Promise<RelayStatus> {
  return invoke<RelayStatus>('stop_relay')
}

export function loginStart(input: {
  providerId: string
  accountId: string
  label: string
  authKind: AuthKind
  idempotencyKey: string
}): Promise<LoginStatus> {
  return invoke<LoginStatus>('login_start', input)
}

export function loginStatus(input: {
  handle: string
  binding: LoginAccountBinding
}): Promise<LoginStatus> {
  return invoke<LoginStatus>('login_status', input)
}

export function loginCancel(input: {
  handle: string
  binding: LoginAccountBinding
}): Promise<LoginStatus> {
  return invoke<LoginStatus>('login_cancel', input)
}

/** Native code fetches the current bound owner action; the caller cannot supply a URL. */
export function loginOpenAuthorization(input: {
  handle: string
  binding: LoginAccountBinding
}): Promise<void> {
  return invoke<void>('login_open_authorization', input)
}

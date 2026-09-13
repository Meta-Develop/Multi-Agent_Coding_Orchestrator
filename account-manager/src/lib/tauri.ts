import { invoke } from '@tauri-apps/api/core'
import type {
  AuthKind,
  LaunchedProcess,
  ProviderAccountList,
  ProviderDescriptor,
  ProviderQuotaList,
  RelayStatus,
  RouteRule,
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

/**
 * Launches only the account already selected in Rust-owned metadata. Account
 * ids, programs, arguments, environment names, paths, and secret values are
 * deliberately absent from this IPC boundary.
 */
export function launchProvider(providerId: string): Promise<LaunchedProcess> {
  return invoke<LaunchedProcess>('launch_provider', { providerId })
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

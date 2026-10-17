import { describe, expect, it } from 'vitest'
import {
  bindingsEqual,
  hasLiveAuthorization,
  isActiveLoginState,
  oauthProgressMessage,
  oauthReadyMessage,
  oauthUnknownMessage,
  shouldStopAutomaticPoll,
  statusMatchesSession,
} from '@/lib/oauthLoginLifecycle'
import type { LoginAccountBinding, LoginStatus } from '@/types'

const binding: LoginAccountBinding = {
  providerId: 'gemini-cli',
  accountId: 'work',
  accountIncarnation: 'inc-1',
}

function status(
  partial: Partial<LoginStatus> & Pick<LoginStatus, 'state'>,
): LoginStatus {
  return {
    handle: 'handle-a',
    binding,
    ...partial,
  }
}

describe('oauthLoginLifecycle', () => {
  it('matches handle and binding exactly for stale guards', () => {
    const ok = status({ state: 'in-progress' })
    expect(statusMatchesSession(ok, 'handle-a', binding)).toBe(true)
    expect(statusMatchesSession(ok, 'handle-b', binding)).toBe(false)
    expect(
      statusMatchesSession(
        status({
          state: 'ready',
          binding: { ...binding, providerId: 'codex-cli' },
        }),
        'handle-a',
        binding,
      ),
    ).toBe(false)
    expect(
      statusMatchesSession(
        status({
          state: 'in-progress',
          binding: { ...binding, accountIncarnation: 'inc-2' },
        }),
        'handle-a',
        binding,
      ),
    ).toBe(false)
  })

  it('treats waiting and in-progress as active', () => {
    expect(isActiveLoginState('waiting-for-user')).toBe(true)
    expect(isActiveLoginState('in-progress')).toBe(true)
    expect(isActiveLoginState('ready')).toBe(false)
    expect(isActiveLoginState('unknown')).toBe(false)
  })

  it('offers only a live unexpired owner action and never terminal authorization', () => {
    const authorization = {
      authorizationUrl: 'https://official.invalid/FAKE-fixture',
      expiresAtUnixMs: 200,
    }
    expect(
      hasLiveAuthorization(
        status({ state: 'waiting-for-user', authorization }),
        100,
      ),
    ).toBe(true)
    expect(
      hasLiveAuthorization(
        status({ state: 'in-progress', authorization }),
        200,
      ),
    ).toBe(false)
    expect(
      hasLiveAuthorization(status({ state: 'waiting-for-user' }), 100),
    ).toBe(false)
    for (const state of ['ready', 'cancelled', 'failed', 'unknown'] as const) {
      expect(hasLiveAuthorization(status({ state, authorization }), 100)).toBe(
        false,
      )
    }
  })

  it('stops automatic poll on terminal states including unknown', () => {
    expect(shouldStopAutomaticPoll('waiting-for-user')).toBe(false)
    expect(shouldStopAutomaticPoll('in-progress')).toBe(false)
    expect(shouldStopAutomaticPoll('ready')).toBe(true)
    expect(shouldStopAutomaticPoll('unknown')).toBe(true)
  })

  it('compares bindings field-wise', () => {
    expect(bindingsEqual(binding, { ...binding })).toBe(true)
    expect(bindingsEqual(binding, { ...binding, accountId: 'other' })).toBe(
      false,
    )
  })

  it.each(['Codex CLI', 'Grok CLI', 'Gemini CLI'])(
    'keeps %s progress and selection separate from model access',
    (displayName) => {
      expect(
        oauthProgressMessage('work', displayName, 'waiting-for-user', false),
      ).toContain(`Signing in to ${displayName} as work`)
      expect(
        oauthProgressMessage('work', displayName, 'waiting-for-user', false),
      ).not.toContain('Google')
      expect(oauthReadyMessage('work', displayName)).toContain(
        'nothing was activated automatically',
      )
      expect(oauthReadyMessage('work', displayName)).toContain(
        'Model access is not established',
      )
      expect(oauthUnknownMessage('work', displayName)).toContain(
        'pending account may remain',
      )
      expect(oauthUnknownMessage('work', displayName)).not.toContain(
        'start again with the same nickname',
      )
    },
  )
})

import { describe, expect, it } from 'vitest'
import {
  bindingsEqual,
  isActiveLoginState,
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
})

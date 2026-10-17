import { act, fireEvent, render, screen } from '@testing-library/react'
import { invoke } from '@tauri-apps/api/core'
import { describe, expect, it, vi } from 'vitest'
import SelectedAccountObservation from './SelectedAccountObservation'
import type {
  AccountObserveResult,
  ModelsObservation,
  ObservedModel,
  SelectedAccountBinding,
} from '@/types'

const binding: SelectedAccountBinding = {
  providerId: 'grok-cli',
  accountId: 'work',
  accountIncarnation: 'incarnation-1',
  selectionRevision: 7,
}

type ObservationFixture = AccountObserveResult & {
  models: {
    content: ModelsObservation & { models: [ObservedModel] }
  }
}

function observation(): ObservationFixture {
  return {
    binding,
    observedAt: '2026-10-03T00:00:00Z',
    auth: { outcome: { kind: 'unavailable' } },
    quota: { outcome: { kind: 'unknown' } },
    models: {
      outcome: { kind: 'observed' },
      content: {
        models: [{ modelId: 'fixture-model', access: 'available' }],
        provenance: {
          sourceKind: 'authenticated-catalog',
          fetchedAt: '2026-10-03T00:00:00Z',
          stale: false,
          principalBinding: binding,
          accessBasis: 'confirmed-model-entitlement',
        },
      },
    },
  }
}

function stub(result: AccountObserveResult, selections = [binding, binding]) {
  vi.mocked(invoke).mockImplementation(async (command) => {
    if (command === 'selected_account_binding')
      return selections.shift() ?? null
    if (command === 'observe_account') return result
    throw new Error('Unexpected fixture IPC')
  })
}

function mount() {
  return render(
    <SelectedAccountObservation
      providerId="grok-cli"
      accountId="work"
      disabled={false}
    />,
  )
}

function check() {
  fireEvent.click(
    screen.getByRole('button', {
      name: 'Check selected account access for grok-cli',
    }),
  )
}

describe('selected account observation', () => {
  it('checks only on request and sends the exact public binding, without selecting or logging in', async () => {
    stub(observation())
    mount()
    expect(invoke).not.toHaveBeenCalled()
    check()
    await screen.findByText('fixture-model: Available')
    expect(invoke).toHaveBeenCalledWith('observe_account', {
      request: { binding, categories: ['auth', 'models', 'quota'] },
    })
    expect(vi.mocked(invoke).mock.calls.map(([command]) => command)).toEqual([
      'selected_account_binding',
      'observe_account',
      'selected_account_binding',
    ])
    expect(screen.getByRole('status')).toHaveTextContent(
      'Auth: Observation unsupported',
    )
    expect(screen.getByRole('status')).toHaveTextContent('Quota: Unknown')
    expect(
      screen.getByText(/Catalog source: Authenticated provider catalog/),
    ).toBeInTheDocument()
  })

  it.each(['missing', 'cache', 'stale', 'unknown'] as const)(
    'never promotes %s catalog evidence into known model access',
    async (kind) => {
      const result = observation()
      const catalog = result.models!.content!
      if (kind === 'missing') delete catalog.provenance
      if (kind === 'cache')
        catalog.provenance!.sourceKind = 'managed-home-cache'
      if (kind === 'stale') catalog.provenance!.stale = true
      if (kind === 'unknown') delete catalog.models[0].access
      stub(result)
      mount()
      check()
      await screen.findByText('fixture-model: Access unknown')
      expect(
        screen.queryByText('fixture-model: Available'),
      ).not.toBeInTheDocument()
      if (kind === 'stale')
        expect(
          screen.getByText(/Catalog metadata is stale/),
        ).toBeInTheDocument()
      if (kind === 'cache')
        expect(
          screen.getByText(/Catalog source: Managed account cache/),
        ).toBeInTheDocument()
    },
  )

  it('preserves confirmed unavailable separately from unknown access', async () => {
    const result = observation()
    result.models!.content!.models[0].access = 'unavailable'
    stub(result)
    mount()
    check()
    await screen.findByText('fixture-model: Unavailable')
  })

  it.each([
    'providerId',
    'accountId',
    'accountIncarnation',
    'selectionRevision',
  ] as const)('refuses a response with another %s', async (field) => {
    const result = observation()
    result.binding = {
      ...binding,
      [field]: field === 'selectionRevision' ? 8 : 'other',
    }
    stub(result)
    mount()
    check()
    await screen.findByText(/Selected account access could not be confirmed/)
    expect(screen.queryByText(/fixture-model:/)).not.toBeInTheDocument()
  })

  it('refuses a different catalog principal even when the outer binding matches', async () => {
    const result = observation()
    result.models!.content!.provenance!.principalBinding = {
      ...binding,
      accountId: 'other',
    }
    stub(result)
    mount()
    check()
    await screen.findByText(/Selected account access could not be confirmed/)
    expect(screen.queryByText(/fixture-model:/)).not.toBeInTheDocument()
  })

  it('refuses a selection revision changed while observation was running', async () => {
    stub(observation(), [binding, { ...binding, selectionRevision: 8 }])
    mount()
    check()
    await screen.findByText(/Selected account access could not be confirmed/)
    expect(screen.queryByText(/fixture-model:/)).not.toBeInTheDocument()
  })

  it('does not observe an account different from the displayed selected account', async () => {
    stub(observation(), [{ ...binding, accountId: 'other' }])
    mount()
    check()
    await screen.findByText(/Selected account access could not be confirmed/)
    expect(vi.mocked(invoke).mock.calls.map(([command]) => command)).toEqual([
      'selected_account_binding',
    ])
  })

  it('discards a pending observation after account selection remounts the view', async () => {
    let resolve: (result: AccountObserveResult) => void = () => {
      throw new Error('Fixture not started')
    }
    const pending = new Promise<AccountObserveResult>((complete) => {
      resolve = complete
    })
    vi.mocked(invoke).mockImplementation(async (command) => {
      if (command === 'selected_account_binding') return binding
      if (command === 'observe_account') return pending
      throw new Error('Unexpected fixture IPC')
    })
    const view = mount()
    check()
    await act(async () => {
      await Promise.resolve()
    })
    view.rerender(
      <SelectedAccountObservation
        key="other"
        providerId="grok-cli"
        accountId="other"
        disabled={false}
      />,
    )
    await act(async () => {
      resolve(observation())
      await pending
    })
    expect(screen.getByRole('status')).toHaveTextContent(
      'Selected account access has not been checked',
    )
    expect(screen.queryByText(/fixture-model:/)).not.toBeInTheDocument()
    expect(vi.mocked(invoke).mock.calls.map(([command]) => command)).toEqual([
      'selected_account_binding',
      'observe_account',
    ])
  })

  it('does not render raw IPC failure text or retry automatically', async () => {
    vi.mocked(invoke).mockRejectedValue(new Error('FAKE-secret-error'))
    mount()
    check()
    await screen.findByText(/Selected account access could not be confirmed/)
    expect(screen.queryByText(/FAKE-secret-error/)).not.toBeInTheDocument()
    expect(invoke).toHaveBeenCalledTimes(1)
  })
})

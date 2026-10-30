import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { invoke } from '@tauri-apps/api/core'
import { describe, expect, it, vi } from 'vitest'
import LaunchOperations from './LaunchOperations'
import {
  AccountMutationProvider,
  useAccountMutation,
} from '@/lib/accountMutation'
import type { LaunchOperationStatus, ProviderDescriptor } from '@/types'

const provider: ProviderDescriptor = {
  id: 'grok-cli',
  displayName: 'Grok CLI',
  vendor: 'xAI',
  authKinds: ['oauth'],
  maturity: 'experimental',
  installState: 'installed',
  capabilities: ['launch-tool'],
}
const running: LaunchOperationStatus = {
  handle: 'a'.repeat(32),
  state: 'running',
  processId: 42,
  exitCode: null,
  failureCode: null,
}

function Start() {
  const { runLaunch } = useAccountMutation()
  return (
    <button onClick={() => void runLaunch(provider, 'Work')}>
      Start fixture
    </button>
  )
}

function fixture() {
  render(
    <AccountMutationProvider>
      <Start />
      <LaunchOperations />
    </AccountMutationProvider>,
  )
  return userEvent.setup()
}

describe('Authority launches', () => {
  it('keeps last confirmed status across cancellation disconnect and recovers by handle', async () => {
    let checked = 0
    vi.mocked(invoke).mockImplementation(async (command) => {
      if (command === 'launch_provider') return running
      if (command === 'launch_cancel')
        throw new Error('private transport detail')
      if (command === 'launch_status') {
        checked += 1
        return checked === 1
          ? { ...running, state: 'cancelling' }
          : { ...running, state: 'cancelled' }
      }
      throw new Error(`Unexpected ${command}`)
    })
    const user = fixture()
    await user.click(screen.getByText('Start fixture'))
    expect(
      await screen.findByText(`Launch ${running.handle}`),
    ).toBeInTheDocument()
    expect(screen.getByRole('status')).toHaveTextContent('running · PID 42')
    await user.click(screen.getByText('Cancel launch'))
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Cancellation outcome unconfirmed',
    )
    expect(screen.getByRole('status')).toHaveTextContent('running')
    expect(
      screen.queryByText(/private transport detail/),
    ).not.toBeInTheDocument()
    await user.click(screen.getByText('Check launch status'))
    expect(screen.getByRole('status')).toHaveTextContent('cancelling')
    await user.click(screen.getByText('Check launch status'))
    expect(screen.getByRole('status')).toHaveTextContent('cancelled')
    expect(screen.queryByText('Cancel launch')).not.toBeInTheDocument()
    expect(invoke).toHaveBeenCalledWith('launch_cancel', {
      handle: running.handle,
    })
    expect(invoke).toHaveBeenCalledWith('launch_status', {
      handle: running.handle,
    })
  })

  it('shows nonzero exit and closed failure status without assuming launch success', async () => {
    vi.mocked(invoke).mockImplementation(async (command) =>
      command === 'launch_provider'
        ? {
            ...running,
            state: 'failed',
            processId: null,
            failureCode: 'unavailable',
          }
        : { ...running, state: 'exited', exitCode: 17 },
    )
    const user = fixture()
    await user.click(screen.getByText('Start fixture'))
    expect(await screen.findByRole('status')).toHaveTextContent(
      'failed · unavailable',
    )
    expect(screen.queryByText('Cancel launch')).not.toBeInTheDocument()
    await user.click(screen.getByText('Check launch status'))
    expect(screen.getByRole('status')).toHaveTextContent(
      'exited · PID 42 · Exit 17',
    )
  })
})

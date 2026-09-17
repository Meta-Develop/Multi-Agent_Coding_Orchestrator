import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { createMemoryRouter, RouterProvider } from 'react-router-dom'
import { invoke } from '@tauri-apps/api/core'
import { describe, expect, it, vi } from 'vitest'
import App from '@/App'
import Dashboard from '@/pages/Dashboard'
import Accounts from '@/pages/Accounts'
import Providers from '@/pages/Providers'
import Relay from '@/pages/Relay'
import RouterRules from '@/pages/RouterRules'
import Settings from '@/pages/Settings'
import type {
  Account,
  LaunchedProcess,
  ProviderAccountList,
  ProviderDescriptor,
} from '@/types'

describe('Accounts page', () => {
  it('shows no Add, Switch, or Delete when the provider advertises nothing', async () => {
    stubInvoke({
      providers: [
        provider({
          id: 'cursor',
          displayName: 'Cursor',
          vendor: 'Anysphere',
          capabilities: [],
        }),
      ],
      listings: [
        listing('cursor', {
          accounts: [
            account({
              id: 'work',
              providerId: 'cursor',
              label: 'Work',
              isStored: true,
            }),
          ],
        }),
      ],
    })
    renderApp()

    await screen.findByRole('heading', { name: 'Cursor' })
    expect(
      screen.queryByRole('button', {
        name: /Add account|Sign in|Import API key/i,
      }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: /Switch/i }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: /Delete/i }),
    ).not.toBeInTheDocument()
  })

  it('offers Claude sign-in and switch that rewrites the live tool config', async () => {
    const user = userEvent.setup()
    const add = vi.fn(async () => undefined)
    stubInvoke({
      providers: [claudeProviderDescriptor()],
      listings: [
        listing('claude-code', {
          accounts: [
            account({
              id: 'claude-code-on-disk',
              providerId: 'claude-code',
              label: 'Live Claude',
              isActive: true,
              isStored: false,
            }),
            account({
              id: 'work',
              providerId: 'claude-code',
              label: 'Work',
              isStored: true,
            }),
          ],
        }),
      ],
      add,
    })
    renderApp()

    await screen.findByRole('heading', { name: 'Claude Code' })
    expect(
      screen.queryByText(/cannot start Claude sign-in/i),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByText(/OAuth is unavailable|cannot start.*sign-in/i),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByText(/cannot switch accounts or select an account/i),
    ).not.toBeInTheDocument()

    const liveRow = screen.getByRole('row', { name: /Live Claude/ })
    expect(
      within(liveRow).queryByRole('button', {
        name: /Switch|Delete|Forget|Launch|Select/,
      }),
    ).not.toBeInTheDocument()

    await user.type(
      screen.getByRole('textbox', { name: 'Nickname' }),
      'personal',
    )
    await user.click(
      screen.getByRole('button', { name: 'Sign in to Claude Code' }),
    )
    expect(add).toHaveBeenCalledWith('claude-code', 'personal', undefined)
    expect(callsOf('add_account').at(-1)?.[1]).toEqual({
      providerId: 'claude-code',
      accountId: 'personal',
    })

    await user.click(screen.getByRole('button', { name: 'Switch to Work' }))
    const switchCopy = screen.getByText(/Switch Claude Code to Work\?/)
    expect(switchCopy).toHaveTextContent(/rewrites the live tool config/i)
    expect(switchCopy).toHaveTextContent(/restorable backup/i)
    expect(switchCopy).not.toHaveTextContent(
      /app-owned launch|launch environment/i,
    )

    await user.click(screen.getByRole('button', { name: 'Cancel switch' }))
    await user.click(screen.getByRole('button', { name: 'Delete Work' }))
    const deleteCopy = screen.getByText(
      /Forget this application's stored copy of Work\?/,
    )
    expect(deleteCopy).toHaveTextContent(/Claude Code is not signed out/i)
    expect(deleteCopy).toHaveTextContent(/own files are left untouched/i)
  })

  it('rejects the reserved Claude live-slot id before calling add_account', async () => {
    const user = userEvent.setup()
    const add = vi.fn(async () => undefined)
    stubInvoke({
      providers: [claudeProviderDescriptor()],
      listings: [listing('claude-code', { accounts: [] })],
      add,
    })
    renderApp()

    await user.type(
      await screen.findByRole('textbox', { name: 'Nickname' }),
      'claude-code-on-disk',
    )
    await user.click(
      screen.getByRole('button', { name: 'Sign in to Claude Code' }),
    )
    expect(screen.getByRole('alert')).toHaveTextContent(
      '`claude-code-on-disk` is reserved for the live on-disk Claude Code identity; choose a different name.',
    )
    expect(add).not.toHaveBeenCalled()
    expect(callsOf('add_account')).toHaveLength(0)
  })

  it('offers Switch and Delete only on stored complete rows', async () => {
    stubInvoke({
      listings: [
        listing('codex-cli', {
          accounts: [
            account({
              id: 'codex-cli-on-disk',
              label: 'Codex CLI',
              maskedIdentity: '****ab12',
              isActive: true,
              isStored: false,
            }),
            account({
              id: 'work',
              label: 'Work',
              maskedIdentity: '****cd34',
              isStored: true,
            }),
            account({
              id: 'unfinished',
              label: 'unfinished',
              maskedIdentity: null,
              authKind: 'unknown',
              isStored: true,
              isIncomplete: true,
            }),
          ],
        }),
      ],
    })
    renderApp()

    await screen.findByRole('table')

    expect(
      screen.queryByRole('button', { name: 'Switch to Codex CLI' }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: 'Delete Codex CLI' }),
    ).not.toBeInTheDocument()

    expect(
      screen.getByRole('button', { name: 'Switch to Work' }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: 'Delete Work' }),
    ).toBeInTheDocument()

    expect(
      screen.queryByRole('button', { name: 'Switch to unfinished' }),
    ).not.toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: 'Delete unfinished' }),
    ).toBeInTheDocument()

    const incompleteRow = screen.getByRole('row', { name: /unfinished/i })
    expect(
      within(incompleteRow).getByText('No usable credential'),
    ).toBeInTheDocument()
    // Visible status is the one-word label so the cell stays on one line;
    // the full explanation is on title (and identity already says the
    // credential is unusable).
    const incompleteStatus = within(incompleteRow).getByTitle(
      'Incomplete — sign-in never finished',
    )
    expect(incompleteStatus).toHaveTextContent(/^Incomplete$/)
  })

  it('renders the table and the damaged-file error for listed-with-error', async () => {
    stubInvoke({
      listings: [
        listing('codex-cli', {
          outcome: {
            kind: 'listed-with-error',
            error: {
              kind: 'config-read',
              path: '/tmp/cam-test/auth.json',
              message:
                'configuration for `codex-cli` could not be read: /tmp/cam-test/auth.json is not valid JSON',
            },
          },
          accounts: [
            account({
              id: 'work',
              label: 'Work',
              maskedIdentity: '****ab12',
              isStored: true,
            }),
          ],
        }),
      ],
    })
    renderApp()

    await screen.findByRole('table')
    expect(screen.getByText(/own login file is damaged/i)).toBeInTheDocument()
    // The adapter path is an inline <code>, so the sentence is no longer
    // one text node. The notice still carries the same error text.
    expect(
      screen.getByText(/own login file is damaged/i).parentElement,
    ).toHaveTextContent(/auth\.json is not valid JSON/)
    expect(screen.queryByText(/Looking failed/i)).not.toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: 'Switch to Work' }),
    ).toBeInTheDocument()
  })

  it('renders the error and no table for a failed listing', async () => {
    stubInvoke({
      listings: [
        listing('codex-cli', {
          outcome: {
            kind: 'failed',
            error: {
              kind: 'config-read',
              path: '/tmp/cam-test/auth.json',
              message:
                'configuration for `codex-cli` could not be read: /tmp/cam-test/auth.json is not valid JSON',
            },
          },
          accounts: [
            account({
              id: 'work',
              label: 'Work',
              maskedIdentity: '****ab12',
              isStored: true,
            }),
          ],
        }),
      ],
    })
    renderApp()

    await screen.findByText(/Looking failed:/)
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: 'Switch to Work' }),
    ).not.toBeInTheDocument()
  })

  it('asks before switch, cancels, confirms, and dismisses on Escape', async () => {
    const user = userEvent.setup()
    const activate = vi.fn(async () => undefined)
    stubInvoke({
      listings: [
        listing('codex-cli', {
          accounts: [
            account({
              id: 'work',
              label: 'Work',
              maskedIdentity: '****ab12',
              isStored: true,
            }),
          ],
        }),
      ],
      activate,
    })
    renderApp()

    await screen.findByRole('button', { name: 'Switch to Work' })

    await user.click(screen.getByRole('button', { name: 'Switch to Work' }))
    expect(screen.getByText(/Switch Codex CLI to Work\?/)).toBeInTheDocument()
    expect(activate).not.toHaveBeenCalled()

    await user.click(screen.getByRole('button', { name: 'Cancel switch' }))
    expect(
      screen.queryByText(/Switch Codex CLI to Work\?/),
    ).not.toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: 'Switch to Work' }),
    ).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Switch to Work' }))
    await user.keyboard('{Escape}')
    expect(
      screen.queryByText(/Switch Codex CLI to Work\?/),
    ).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Switch to Work' }))
    await user.click(
      screen.getByRole('button', { name: 'Confirm switch to Work' }),
    )
    expect(activate).toHaveBeenCalledTimes(1)
    expect(activate).toHaveBeenCalledWith('codex-cli', 'work')
  })

  it('shows a failed mutation as an alert and keeps the previous listing', async () => {
    const user = userEvent.setup()
    stubInvoke({
      listings: [
        listing('codex-cli', {
          accounts: [
            account({
              id: 'work',
              label: 'Work',
              maskedIdentity: '****ab12',
              isStored: true,
            }),
            account({
              id: 'personal',
              label: 'Personal',
              maskedIdentity: '****cd34',
              isActive: true,
              isStored: true,
            }),
          ],
        }),
      ],
      activate: async () => {
        throw 'Codex CLI appears to be running (process name `codex`). Close the Codex CLI before switching.'
      },
    })
    renderApp()

    await screen.findByRole('button', { name: 'Switch to Work' })
    const listsBefore = callsOf('list_accounts').length

    await user.click(screen.getByRole('button', { name: 'Switch to Work' }))
    await user.click(
      screen.getByRole('button', { name: 'Confirm switch to Work' }),
    )

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('Could not switch Codex CLI to Work:')
    expect(alert).toHaveTextContent(
      'Codex CLI appears to be running (process name `codex`). Close the Codex CLI before switching.',
    )
    expect(callsOf('list_accounts')).toHaveLength(listsBefore)
    expect(screen.getByRole('table')).toBeInTheDocument()
    expect(
      within(screen.getByRole('row', { name: /Personal/ })).getByText('Active'),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: 'Switch to Work' }),
    ).toBeInTheDocument()
  })

  it('re-fetches the listing after a successful mutation instead of editing it in place', async () => {
    const user = userEvent.setup()
    let listings: ProviderAccountList[] = [
      listing('codex-cli', {
        accounts: [
          account({
            id: 'work',
            label: 'Work',
            maskedIdentity: '****ab12',
            isStored: true,
          }),
          account({
            id: 'personal',
            label: 'Personal',
            maskedIdentity: '****cd34',
            isActive: true,
            isStored: true,
          }),
        ],
      }),
    ]
    stubInvoke({
      listings: () => listings,
      activate: async () => {
        listings = [
          listing('codex-cli', {
            accounts: [
              account({
                id: 'work',
                label: 'Work',
                maskedIdentity: '****zz99',
                isActive: true,
                isStored: true,
              }),
              account({
                id: 'personal',
                label: 'Personal',
                maskedIdentity: '****cd34',
                isStored: true,
              }),
            ],
          }),
        ]
      },
    })
    renderApp()

    await screen.findByText('****ab12')
    const listsBefore = callsOf('list_accounts').length

    await user.click(screen.getByRole('button', { name: 'Switch to Work' }))
    await user.click(
      screen.getByRole('button', { name: 'Confirm switch to Work' }),
    )

    expect(await screen.findByText('****zz99')).toBeInTheDocument()
    expect(screen.queryByText('****ab12')).not.toBeInTheDocument()
    expect(
      within(screen.getByRole('row', { name: /Work/ })).getByText('Active'),
    ).toBeInTheDocument()
    expect(callsOf('list_accounts').length).toBeGreaterThan(listsBefore)
  })

  it('disables mutating controls while a mutation is running, including after remount', async () => {
    const user = userEvent.setup()
    let finishAdd!: () => void
    stubInvoke({
      listings: [
        listing('codex-cli', {
          accounts: [
            account({
              id: 'work',
              label: 'Work',
              maskedIdentity: '****ab12',
              isStored: true,
            }),
          ],
        }),
      ],
      add: () =>
        new Promise<void>((resolve) => {
          finishAdd = resolve
        }),
    })
    renderApp()

    await screen.findByRole('textbox', { name: 'Nickname' })
    await user.type(
      screen.getByRole('textbox', { name: 'Nickname' }),
      'unfinished',
    )
    await user.click(
      screen.getByRole('button', { name: 'Sign in to Codex CLI' }),
    )

    expect(
      await screen.findByText(/Signing in to Codex CLI as unfinished/),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: 'Sign in to Codex CLI' }),
    ).toBeDisabled()
    expect(screen.getByRole('textbox', { name: 'Nickname' })).toBeDisabled()
    expect(
      screen.getByRole('button', { name: 'Switch to Work' }),
    ).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Delete Work' })).toBeDisabled()
    expect(screen.queryByText(/cancell/i)).not.toBeInTheDocument()

    await user.click(screen.getByRole('link', { name: 'Dashboard' }))
    expect(
      screen.getByText(/Signing in to Codex CLI as unfinished/),
    ).toBeInTheDocument()
    expect(screen.queryByText(/cancell/i)).not.toBeInTheDocument()
    expect(
      screen.queryByRole('textbox', { name: 'Nickname' }),
    ).not.toBeInTheDocument()

    await user.click(screen.getByRole('link', { name: 'Accounts' }))
    expect(
      await screen.findByRole('button', { name: 'Sign in to Codex CLI' }),
    ).toBeDisabled()
    expect(
      screen.getByText(/Signing in to Codex CLI as unfinished/),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: 'Switch to Work' }),
    ).toBeDisabled()
    expect(screen.queryByText(/cancell/i)).not.toBeInTheDocument()

    finishAdd()
  })

  it('rejects an id the backend would reject before calling add_account', async () => {
    const user = userEvent.setup()
    const add = vi.fn(async () => undefined)
    stubInvoke({
      listings: [listing('codex-cli', { accounts: [] })],
      add,
    })
    renderApp()

    const name = await screen.findByRole('textbox', { name: 'Nickname' })
    const submit = screen.getByRole('button', {
      name: 'Sign in to Codex CLI',
    })

    await user.click(submit)
    expect(screen.getByRole('alert')).toHaveTextContent(
      'Enter an account name.',
    )
    expect(add).not.toHaveBeenCalled()

    await user.type(name, 'acct/work')
    await user.click(submit)
    expect(screen.getByRole('alert')).toHaveTextContent(
      'Use only letters, digits, `-` and `_`, at most 128 characters.',
    )
    expect(add).not.toHaveBeenCalled()

    await user.clear(name)
    await user.type(name, 'codex-cli-on-disk')
    await user.click(submit)
    expect(screen.getByRole('alert')).toHaveTextContent(
      '`codex-cli-on-disk` is reserved for the live on-disk Codex identity; choose a different name.',
    )
    expect(add).not.toHaveBeenCalled()
    expect(callsOf('add_account')).toHaveLength(0)
  })

  it('renders launch selection independently from the active tool identity', async () => {
    stubInvoke({
      providers: [
        provider({
          id: 'gemini-cli',
          displayName: 'Gemini CLI',
          vendor: 'Google',
          capabilities: [
            'add-account',
            'switch-account',
            'delete-account',
            'launch-tool',
          ],
        }),
      ],
      listings: [
        listing('gemini-cli', {
          accounts: [
            account({
              id: 'selected',
              providerId: 'gemini-cli',
              label: 'Selected',
              authKind: 'api-key',
              isSelectedForLaunch: true,
            }),
            account({
              id: 'google-work',
              providerId: 'gemini-cli',
              label: 'Google work',
              authKind: 'oauth',
            }),
            account({
              id: 'active',
              providerId: 'gemini-cli',
              label: 'Active elsewhere',
              authKind: 'api-key',
              isActive: true,
            }),
            account({
              id: 'unfinished',
              providerId: 'gemini-cli',
              label: 'Unfinished',
              authKind: 'api-key',
              isSelectedForLaunch: true,
              isIncomplete: true,
            }),
          ],
        }),
      ],
    })
    renderApp()

    const selectedRow = await screen.findByRole('row', { name: /Selected/ })
    const oauthRow = screen.getByRole('row', { name: /Google work/ })
    const activeRow = screen.getByRole('row', { name: /Active elsewhere/ })
    expect(within(oauthRow).getByText('oauth')).toBeInTheDocument()
    expect(
      screen.queryByText(/does not support Google OAuth/i),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByText(/Google OAuth accounts are not supported/i),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByText(/lists API-key accounts only/i),
    ).not.toBeInTheDocument()
    expect(
      within(selectedRow).getByText('Selected for app launch'),
    ).toBeInTheDocument()
    expect(within(selectedRow).queryByText(/^Active$/)).not.toBeInTheDocument()
    expect(within(activeRow).getByText(/^Active$/)).toBeInTheDocument()
    expect(
      within(activeRow).queryByText('Selected for app launch'),
    ).not.toBeInTheDocument()
    expect(
      within(selectedRow).getByRole('button', { name: 'Launch Selected' }),
    ).toBeInTheDocument()
    expect(
      within(selectedRow).queryByRole('button', {
        name: /Select Selected for app launch/,
      }),
    ).not.toBeInTheDocument()
    expect(
      within(activeRow).getByRole('button', {
        name: 'Select Active elsewhere for app launch',
      }),
    ).toBeInTheDocument()
    expect(
      within(screen.getByRole('row', { name: /Unfinished/ })).queryByRole(
        'button',
        { name: /Launch Unfinished/ },
      ),
    ).not.toBeInTheDocument()
  })

  it('confirms launch selection as metadata-only and invokes activation with public ids', async () => {
    const user = userEvent.setup()
    const activate = vi.fn(async () => undefined)
    stubInvoke({
      providers: [launchProviderDescriptor('gemini-cli', 'Gemini CLI')],
      listings: [
        listing('gemini-cli', {
          accounts: [
            account({
              id: 'work',
              providerId: 'gemini-cli',
              label: 'Work',
              authKind: 'oauth',
            }),
          ],
        }),
      ],
      activate,
    })
    renderApp()

    await user.click(
      await screen.findByRole('button', {
        name: 'Select Work for app launch',
      }),
    )
    expect(
      screen.getByText(/changes manager metadata only/i),
    ).toHaveTextContent(/affects only a process launched by this application/i)
    expect(
      screen.getByText(/changes manager metadata only/i),
    ).toHaveTextContent(/does not rewrite the tool's configuration/i)
    await user.click(
      screen.getByRole('button', {
        name: 'Confirm selection of Work for app launch',
      }),
    )

    expect(activate).toHaveBeenCalledWith('gemini-cli', 'work')
    expect(callsOf('activate_account').at(-1)?.[1]).toEqual({
      providerId: 'gemini-cli',
      accountId: 'work',
    })
    expect(
      await screen.findByText(/Selected Work for Gemini CLI app launches/),
    ).toBeInTheDocument()
  })

  it('launches only the selected complete account with provider-id-only IPC', async () => {
    const user = userEvent.setup()
    const launch = vi.fn(async (): Promise<LaunchedProcess> => ({
      providerId: 'gemini-cli',
      accountId: 'work',
      processId: 4242,
    }))
    stubInvoke({
      providers: [launchProviderDescriptor('gemini-cli', 'Gemini CLI')],
      listings: [
        listing('gemini-cli', {
          accounts: [
            account({
              id: 'work',
              providerId: 'gemini-cli',
              label: 'Work',
              authKind: 'oauth',
              isSelectedForLaunch: true,
            }),
          ],
        }),
      ],
      launch,
    })
    renderApp()

    await user.click(await screen.findByRole('button', { name: 'Launch Work' }))

    expect(launch).toHaveBeenCalledWith('gemini-cli')
    expect(callsOf('launch_provider')).toHaveLength(1)
    expect(callsOf('launch_provider')[0]?.[1]).toEqual({
      providerId: 'gemini-cli',
    })
    expect(
      await screen.findByText(
        /Launched an app-owned Gemini CLI child for work \(PID 4242\)/,
      ),
    ).toBeInTheDocument()
    expect(screen.getByText(/app-owned Gemini CLI child/i)).toHaveTextContent(
      /External launches and already-running sessions are unchanged/i,
    )
  })

  it('reports launch refusal without claiming an external session changed', async () => {
    const user = userEvent.setup()
    stubInvoke({
      providers: [launchProviderDescriptor('grok-cli', 'Grok CLI')],
      listings: [
        listing('grok-cli', {
          accounts: [
            account({
              id: 'work',
              providerId: 'grok-cli',
              label: 'Work',
              isSelectedForLaunch: true,
            }),
          ],
        }),
      ],
      launch: async () => {
        throw 'vendor lock is held'
      },
    })
    renderApp()

    await user.click(await screen.findByRole('button', { name: 'Launch Work' }))
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent(
      'Could not launch Grok CLI for Work: vendor lock is held',
    )
    expect(alert).not.toHaveTextContent(/switched|active session changed/i)
  })

  it('offers Gemini Google sign-in and sends oauth without a password field', async () => {
    const user = userEvent.setup()
    const add = vi.fn(async () => undefined)
    stubInvoke({
      providers: [launchProviderDescriptor('gemini-cli', 'Gemini CLI')],
      listings: [listing('gemini-cli')],
      add,
    })
    renderApp()

    expect(
      await screen.findByRole('heading', { name: 'Sign in to Gemini CLI' }),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/Nothing is configured for this provider/i),
    ).toBeInTheDocument()
    expect(
      screen.queryByText(/does not support Google OAuth/i),
    ).not.toBeInTheDocument()
    expect(
      screen.getByText(/browser completes Google sign-in/i),
    ).toHaveTextContent(/never takes a password/i)
    expect(screen.queryByLabelText(/password/i)).not.toBeInTheDocument()
    await user.type(screen.getByRole('textbox', { name: 'Nickname' }), 'work')
    await user.click(
      screen.getByRole('button', { name: 'Sign in to Gemini CLI' }),
    )

    expect(add).toHaveBeenCalledWith('gemini-cli', 'work', 'oauth')
    expect(callsOf('add_account').at(-1)?.[1]).toEqual({
      providerId: 'gemini-cli',
      accountId: 'work',
      authKind: 'oauth',
    })
  })

  it('imports a Gemini API key as a secondary path and sends no key through IPC', async () => {
    const user = userEvent.setup()
    const add = vi.fn(async () => undefined)
    stubInvoke({
      providers: [launchProviderDescriptor('gemini-cli', 'Gemini CLI')],
      listings: [listing('gemini-cli')],
      add,
    })
    renderApp()

    expect(
      await screen.findByRole('heading', { name: 'Import API key' }),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/Start or restart this application with/i),
    ).toHaveTextContent(/GEMINI_API_KEY/)
    expect(
      screen.getByText(/Start or restart this application with/i),
    ).toHaveTextContent(/different source key/)
    const explanation = screen.getByText(
      /parent-process key into CredentialStore/i,
    )
    expect(explanation).toHaveTextContent(
      /never typed into or returned to this webview/i,
    )
    expect(explanation).not.toHaveTextContent(
      /Google OAuth is not offered here/i,
    )
    await user.type(screen.getByRole('textbox', { name: 'Nickname' }), 'work')
    await user.click(
      screen.getByRole('button', { name: 'Import API key for Gemini CLI' }),
    )

    expect(add).toHaveBeenCalledWith('gemini-cli', 'work', 'api-key')
    expect(callsOf('add_account').at(-1)?.[1]).toEqual({
      providerId: 'gemini-cli',
      accountId: 'work',
      authKind: 'api-key',
    })
  })

  it('warns that forgetting Grok metadata retains the vendor home and credential', async () => {
    const user = userEvent.setup()
    const remove = vi.fn(async () => undefined)
    stubInvoke({
      providers: [launchProviderDescriptor('grok-cli', 'Grok CLI')],
      listings: [
        listing('grok-cli', {
          accounts: [
            account({
              id: 'work',
              providerId: 'grok-cli',
              label: 'Work',
            }),
          ],
        }),
      ],
      remove,
    })
    renderApp()

    expect(
      await screen.findByRole('button', { name: 'Sign in to Grok CLI' }),
    ).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Forget Work' }))
    expect(screen.getByText(/vendor-written isolated home/i)).toHaveTextContent(
      /credential deliberately remain on disk/i,
    )
    expect(screen.getByText(/vendor-written isolated home/i)).toHaveTextContent(
      /does not sign out Grok CLI or destroy its credential/i,
    )
    await user.click(
      screen.getByRole('button', { name: 'Confirm forgetting Work' }),
    )
    expect(remove).toHaveBeenCalledWith('grok-cli', 'work')
  })

  it('lists a live Gemini OAuth row as a read-only on-disk identity', async () => {
    stubInvoke({
      providers: [launchProviderDescriptor('gemini-cli', 'Gemini CLI')],
      listings: [
        listing('gemini-cli', {
          accounts: [
            account({
              id: 'gemini-cli-on-disk',
              providerId: 'gemini-cli',
              label: 'On-disk Gemini OAuth',
              authKind: 'oauth',
              isStored: false,
            }),
            account({
              id: 'work',
              providerId: 'gemini-cli',
              label: 'Work',
              authKind: 'oauth',
              isStored: true,
            }),
          ],
        }),
      ],
    })
    renderApp()

    const liveRow = await screen.findByRole('row', {
      name: /On-disk Gemini OAuth/,
    })
    expect(within(liveRow).getByText('oauth')).toBeInTheDocument()
    expect(
      within(liveRow).queryByRole('button', {
        name: /Select|Forget|Launch|Switch|Delete/,
      }),
    ).not.toBeInTheDocument()

    const storedRow = screen.getByRole('row', { name: /^Work/ })
    expect(
      within(storedRow).getByRole('button', {
        name: 'Select Work for app launch',
      }),
    ).toBeInTheDocument()
    expect(
      within(storedRow).getByRole('button', { name: 'Forget Work' }),
    ).toBeInTheDocument()
    expect(
      within(storedRow).queryByRole('button', { name: /Launch Work/ }),
    ).not.toBeInTheDocument()
  })

  it('warns that forgetting Gemini OAuth metadata retains the isolated home', async () => {
    const user = userEvent.setup()
    const remove = vi.fn(async () => undefined)
    stubInvoke({
      providers: [launchProviderDescriptor('gemini-cli', 'Gemini CLI')],
      listings: [
        listing('gemini-cli', {
          accounts: [
            account({
              id: 'work',
              providerId: 'gemini-cli',
              label: 'Work',
              authKind: 'oauth',
            }),
          ],
        }),
      ],
      remove,
    })
    renderApp()

    await user.click(await screen.findByRole('button', { name: 'Forget Work' }))
    expect(screen.getByText(/vendor-written isolated home/i)).toHaveTextContent(
      /credential deliberately remain on disk/i,
    )
    expect(screen.getByText(/vendor-written isolated home/i)).toHaveTextContent(
      /does not sign out Gemini CLI or destroy its credential/i,
    )
    await user.click(
      screen.getByRole('button', { name: 'Confirm forgetting Work' }),
    )
    expect(remove).toHaveBeenCalledWith('gemini-cli', 'work')
  })
})

function renderApp(path = '/accounts') {
  const router = createMemoryRouter(
    [
      {
        path: '/',
        element: <App />,
        children: [
          { index: true, element: <Dashboard /> },
          { path: 'accounts', element: <Accounts /> },
          { path: 'providers', element: <Providers /> },
          { path: 'relay', element: <Relay /> },
          { path: 'router', element: <RouterRules /> },
          { path: 'settings', element: <Settings /> },
        ],
      },
    ],
    { initialEntries: [path] },
  )
  return render(<RouterProvider router={router} />)
}

function stubInvoke(options: {
  providers?: ProviderDescriptor[]
  listings?: ProviderAccountList[] | (() => ProviderAccountList[])
  add?: (
    providerId: string,
    accountId: string,
    authKind?: string,
  ) => Promise<void>
  activate?: (providerId: string, accountId: string) => Promise<void>
  remove?: (providerId: string, accountId: string) => Promise<void>
  launch?: (providerId: string) => Promise<LaunchedProcess>
}) {
  const providers = options.providers ?? [provider()]
  vi.mocked(invoke).mockImplementation(async (command, args) => {
    const payload = (args ?? {}) as {
      providerId?: string | null
      accountId?: string
      authKind?: string
    }
    switch (command) {
      case 'list_providers':
        return providers
      case 'list_accounts':
        return typeof options.listings === 'function'
          ? options.listings()
          : (options.listings ?? [])
      case 'add_account':
        if (options.add) {
          await options.add(
            payload.providerId ?? '',
            payload.accountId ?? '',
            payload.authKind,
          )
        }
        return undefined
      case 'activate_account':
        if (options.activate) {
          await options.activate(
            payload.providerId ?? '',
            payload.accountId ?? '',
          )
        }
        return undefined
      case 'delete_account':
        if (options.remove) {
          await options.remove(
            payload.providerId ?? '',
            payload.accountId ?? '',
          )
        }
        return undefined
      case 'launch_provider':
        if (options.launch) {
          return options.launch(payload.providerId ?? '')
        }
        throw new Error('launch was not stubbed')
      default:
        throw new Error(`unexpected command: ${String(command)}`)
    }
  })
}

function claudeProviderDescriptor(): ProviderDescriptor {
  return provider({
    id: 'claude-code',
    displayName: 'Claude Code',
    vendor: 'Anthropic',
    capabilities: ['add-account', 'switch-account', 'delete-account'],
  })
}

function launchProviderDescriptor(
  id: string,
  displayName: string,
): ProviderDescriptor {
  return provider({
    id,
    displayName,
    vendor:
      id === 'gemini-cli' ? 'Google' : id === 'grok-cli' ? 'xAI' : 'Unknown',
    capabilities: [
      'add-account',
      'switch-account',
      'delete-account',
      'launch-tool',
    ],
  })
}

function callsOf(command: string) {
  return vi.mocked(invoke).mock.calls.filter(([name]) => name === command)
}

function provider(
  partial: Partial<ProviderDescriptor> = {},
): ProviderDescriptor {
  return {
    id: 'codex-cli',
    displayName: 'Codex CLI',
    vendor: 'OpenAI',
    authKinds: ['oauth', 'api-key'],
    maturity: 'experimental',
    installState: 'installed',
    capabilities: ['add-account', 'switch-account', 'delete-account'],
    ...partial,
  }
}

function listing(
  providerId: string,
  partial: Partial<ProviderAccountList> = {},
): ProviderAccountList {
  return {
    providerId,
    accounts: [],
    outcome: { kind: 'listed' },
    ...partial,
  }
}

function account(partial: Partial<Account> & Pick<Account, 'id'>): Account {
  return {
    providerId: 'codex-cli',
    label: partial.id,
    maskedIdentity: '****ab12',
    authKind: 'oauth',
    isActive: false,
    isSelectedForLaunch: false,
    isStored: true,
    isIncomplete: false,
    expiresAt: null,
    ...partial,
  }
}

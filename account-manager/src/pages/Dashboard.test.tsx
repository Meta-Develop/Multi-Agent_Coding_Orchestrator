import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import Dashboard from '@/pages/Dashboard'
import { listAccounts, listProviders, listQuota } from '@/lib/tauri'
import type {
  Account,
  ProviderAccountList,
  ProviderDescriptor,
  ProviderQuotaList,
} from '@/types'

vi.mock('@/lib/tauri', () => ({
  listAccounts: vi.fn(),
  listProviders: vi.fn(),
  listQuota: vi.fn(),
}))

describe('Dashboard quota visibility', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(listProviders).mockResolvedValue(PROVIDERS)
    vi.mocked(listAccounts).mockResolvedValue(
      PROVIDERS.map((item) => listing(item)),
    )
    vi.mocked(listQuota).mockResolvedValue(
      PROVIDERS.map((item) => noSignal(item.id)),
    )
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('keeps the account name visible next to an honest no-signal state', async () => {
    render(<Dashboard />)

    for (const provider of PROVIDERS) {
      const name = accountLabel(provider)
      const card = await screen.findByRole('article', {
        name: `${name} quota`,
      })
      expect(within(card).getByText(name)).toBeVisible()
      expect(within(card).getByText(provider.displayName)).toBeVisible()
      expect(within(card).getByText('No quota signal available')).toBeVisible()
      expect(within(card).queryByText(/% remaining/)).not.toBeInTheDocument()
      expect(within(card).queryByRole('progressbar')).not.toBeInTheDocument()
      expect(within(card).getByText('—')).toBeVisible()
    }
  })

  it('switches between accessible grid and list views', async () => {
    const user = userEvent.setup()
    render(<Dashboard />)

    expect(
      await screen.findByRole('list', { name: 'Quota grid' }),
    ).toBeVisible()
    expect(screen.getByRole('button', { name: 'Grid' })).toHaveAttribute(
      'aria-pressed',
      'true',
    )
    expect(screen.getByRole('button', { name: 'List' })).toHaveAttribute(
      'aria-pressed',
      'false',
    )

    await user.click(screen.getByRole('button', { name: 'List' }))

    expect(screen.getByRole('list', { name: 'Quota list' })).toBeVisible()
    expect(screen.getByRole('button', { name: 'List' })).toHaveAttribute(
      'aria-pressed',
      'true',
    )
    expect(screen.getAllByRole('article')).toHaveLength(PROVIDERS.length)
    expect(
      screen.getByRole('article', {
        name: `${accountLabel(CLAUDE_PROVIDER)} quota`,
      }),
    ).toBeVisible()
  })

  it('shows name, remaining quota, and reset on the same sourced card', async () => {
    const provider = CLAUDE_PROVIDER
    const capturedAt = '2026-08-20T10:00:00Z'
    const resetsAt = '2026-08-20T15:00:00Z'
    vi.mocked(listProviders).mockResolvedValue([provider])
    vi.mocked(listAccounts).mockResolvedValue([
      listing(provider, [account(provider, { id: 'work', label: 'Work' })]),
    ])
    vi.mocked(listQuota).mockResolvedValue([
      {
        providerId: provider.id,
        planLabel: 'Pro',
        outcome: { kind: 'available' },
        snapshots: [
          {
            accountId: 'work',
            model: 'claude-sonnet',
            utilization: 0.25,
            windowLabel: '5 hours',
            resetsAt,
            capturedAt,
            source: 'local-file',
          },
        ],
      },
    ])

    render(<Dashboard />)

    const card = await screen.findByRole('article', {
      name: 'Work quota',
    })
    expect(within(card).getByText('Work')).toBeVisible()
    expect(within(card).getByText(provider.displayName)).toBeVisible()
    expect(within(card).getByText('75% remaining')).toBeVisible()
    expect(within(card).getByRole('progressbar')).toHaveAttribute(
      'aria-valuenow',
      '75',
    )
    expect(within(card).getByText('Pro')).toBeVisible()
    expect(within(card).getByText('5 hours')).toBeVisible()
    expect(within(card).getByTitle(resetsAt)).toHaveAttribute(
      'dateTime',
      resetsAt,
    )
  })

  it('renders collection failures distinctly from no-signal states', async () => {
    const failedProvider = CLAUDE_PROVIDER
    const emptyProvider = CODEX_PROVIDER
    vi.mocked(listProviders).mockResolvedValue([failedProvider, emptyProvider])
    vi.mocked(listAccounts).mockResolvedValue([
      listing(failedProvider),
      listing(emptyProvider),
    ])
    vi.mocked(listQuota).mockResolvedValue([
      {
        providerId: failedProvider.id,
        planLabel: null,
        snapshots: [],
        outcome: {
          kind: 'failed',
          error: {
            kind: 'config-read',
            path: null,
            message: 'Quota cache is unreadable',
          },
        },
      },
      noSignal(emptyProvider.id),
    ])

    render(<Dashboard />)

    const failedCard = await screen.findByRole('article', {
      name: `${accountLabel(failedProvider)} quota`,
    })
    expect(
      within(failedCard).getByText(accountLabel(failedProvider)),
    ).toBeVisible()
    expect(within(failedCard).getByRole('alert')).toHaveTextContent(
      'Quota collection failed: Quota cache is unreadable',
    )
    expect(
      within(failedCard).queryByText('No quota signal available'),
    ).not.toBeInTheDocument()

    const emptyCard = screen.getByRole('article', {
      name: `${accountLabel(emptyProvider)} quota`,
    })
    expect(
      within(emptyCard).getByText(accountLabel(emptyProvider)),
    ).toBeVisible()
    expect(
      within(emptyCard).getByText('No quota signal available'),
    ).toBeVisible()
    expect(within(emptyCard).queryByRole('alert')).not.toBeInTheDocument()
    expect(within(emptyCard).getByText('—')).toBeVisible()
  })

  it('treats a missing provider result as an error', async () => {
    vi.mocked(listProviders).mockResolvedValue([CLAUDE_PROVIDER])
    vi.mocked(listAccounts).mockResolvedValue([listing(CLAUDE_PROVIDER)])
    vi.mocked(listQuota).mockResolvedValue([])

    render(<Dashboard />)

    const card = await screen.findByRole('article', {
      name: `${accountLabel(CLAUDE_PROVIDER)} quota`,
    })
    expect(within(card).getByText(accountLabel(CLAUDE_PROVIDER))).toBeVisible()
    expect(within(card).getByRole('alert')).toHaveTextContent(
      'Quota result missing for this provider.',
    )
    expect(
      within(card).queryByText('No quota signal available'),
    ).not.toBeInTheDocument()
  })

  it('keeps the account row when quota loading rejects', async () => {
    vi.mocked(listProviders).mockResolvedValue([CLAUDE_PROVIDER])
    vi.mocked(listAccounts).mockResolvedValue([listing(CLAUDE_PROVIDER)])
    vi.mocked(listQuota).mockImplementation(() => {
      throw new Error('quota command unavailable')
    })

    render(<Dashboard />)

    const card = await screen.findByRole('article', {
      name: `${accountLabel(CLAUDE_PROVIDER)} quota`,
    })
    expect(within(card).getByText(accountLabel(CLAUDE_PROVIDER))).toBeVisible()
    expect(within(card).getByRole('alert')).toHaveTextContent(
      'Quota collection failed: Error: quota command unavailable',
    )
  })
})

const CLAUDE_PROVIDER = provider('claude-code', 'Claude Code')
const CODEX_PROVIDER = provider('codex-cli', 'Codex CLI')
const PROVIDERS: ProviderDescriptor[] = [
  CLAUDE_PROVIDER,
  CODEX_PROVIDER,
  provider('cursor', 'Cursor', 'planned'),
  provider('grok-cli', 'Grok CLI'),
  provider('gemini-cli', 'Gemini CLI'),
]

function provider(
  id: string,
  displayName: string,
  maturity: ProviderDescriptor['maturity'] = 'experimental',
): ProviderDescriptor {
  return {
    id,
    displayName,
    vendor: 'Vendor',
    authKinds: ['oauth'],
    maturity,
    installState: 'installed',
    capabilities: [],
  }
}

function accountLabel(item: ProviderDescriptor): string {
  return `${item.displayName} work`
}

function account(
  item: ProviderDescriptor,
  partial: Partial<Account> = {},
): Account {
  return {
    id: `${item.id}-work`,
    providerId: item.id,
    label: accountLabel(item),
    maskedIdentity: 'a***@example.com',
    authKind: 'oauth',
    isActive: false,
    isSelectedForLaunch: false,
    isStored: true,
    isIncomplete: false,
    expiresAt: null,
    ...partial,
  }
}

function listing(
  item: ProviderDescriptor,
  accounts: Account[] = [account(item)],
): ProviderAccountList {
  return {
    providerId: item.id,
    accounts,
    outcome: { kind: 'listed' },
  }
}

function noSignal(providerId: string): ProviderQuotaList {
  return {
    providerId,
    planLabel: null,
    snapshots: [],
    outcome: { kind: 'no-signal' },
  }
}

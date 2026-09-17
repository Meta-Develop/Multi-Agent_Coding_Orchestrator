import { useId, useState, type FormEvent, type ReactNode } from 'react'
import type { AuthKind, ProviderDescriptor } from '@/types'

const ACCOUNT_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/
const ACCOUNT_ID_MAX_LENGTH = 128

/**
 * Adds a stored account for one adapter. The nickname is the account id.
 * Codex, Claude, and Grok start vendor sign-in; Gemini opens the system
 * browser for Google sign-in, and can also import GEMINI_API_KEY from the
 * native parent process. This webview never accepts a secret.
 */
export default function AddAccountForm({
  provider,
  disabled,
  onAdd,
}: {
  provider: ProviderDescriptor
  disabled: boolean
  onAdd: (accountId: string, authKind?: AuthKind) => Promise<boolean>
}) {
  const id = useId()
  const nameId = `${id}-name`
  const rulesId = `${id}-rules`
  const explanationId = `${id}-explanation`
  const importExplanationId = `${id}-import-explanation`
  const errorId = `${id}-error`
  const [name, setName] = useState('')
  const [validation, setValidation] = useState<string | null>(null)
  const flow = addFlow(provider)
  const isGemini = provider.id === 'gemini-cli'

  async function add(authKind?: AuthKind) {
    const accountId = name.trim()
    const problem = accountIdProblem(accountId, provider.id)
    if (problem !== null) {
      setValidation(problem)
      return
    }
    const added = await onAdd(accountId, authKind)
    if (added) {
      setName('')
      setValidation(null)
    }
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    await add(isGemini ? 'oauth' : undefined)
  }

  const describedBy = [
    rulesId,
    explanationId,
    validation !== null ? errorId : null,
  ]
    .filter((value): value is string => value !== null)
    .join(' ')

  return (
    <form
      className="mt-5"
      onSubmit={(event) => {
        void handleSubmit(event)
      }}
    >
      <h3 className="text-sm font-semibold tracking-tight">{flow.heading}</h3>
      <ol className="mt-3 list-decimal space-y-4 pl-5 text-sm">
        <li>
          <label htmlFor={nameId} className="block font-medium">
            Nickname
          </label>
          <input
            id={nameId}
            type="text"
            name="accountName"
            value={name}
            maxLength={ACCOUNT_ID_MAX_LENGTH}
            autoComplete="off"
            spellCheck={false}
            disabled={disabled}
            aria-invalid={validation !== null}
            aria-describedby={describedBy}
            onChange={(event) => {
              setName(event.target.value)
              if (validation !== null) {
                setValidation(null)
              }
            }}
            className="field mt-1 max-w-md"
          />
          <p id={rulesId} className="mt-1.5 text-ink-muted">
            The nickname becomes the account&apos;s id. Use letters, digits,{' '}
            <code className="font-mono">-</code> and{' '}
            <code className="font-mono">_</code>, at most{' '}
            {ACCOUNT_ID_MAX_LENGTH} characters.
          </p>
        </li>
        {flow.steps.map((step, index) => (
          <li key={index} className="text-ink-muted">
            {step}
          </li>
        ))}
        <li>
          <button type="submit" disabled={disabled} className="btn btn-primary">
            {flow.submitLabel}
          </button>
          <p id={explanationId} className="mt-1.5 text-ink-muted">
            {flow.submitHint}
          </p>
        </li>
      </ol>
      {isGemini && (
        <div className="mt-6">
          <h3 className="text-sm font-semibold tracking-tight">
            Import API key
          </h3>
          <ol
            className="mt-3 list-decimal space-y-4 pl-5 text-sm"
            start={flow.steps.length + 2}
          >
            <li className="text-ink-muted">
              Start or restart this application with{' '}
              <code className="font-mono">GEMINI_API_KEY</code> set in the
              native parent process. Restart again with a different source key
              before importing another account.
            </li>
            <li>
              <button
                type="button"
                disabled={disabled}
                className="btn"
                onClick={() => {
                  void add('api-key')
                }}
              >
                Import API key for {provider.displayName}
              </button>
              <p id={importExplanationId} className="mt-1.5 text-ink-muted">
                This copies the parent-process key into CredentialStore. The key
                is never typed into or returned to this webview.
              </p>
            </li>
          </ol>
        </div>
      )}
      {validation !== null && (
        <p id={errorId} className="mt-3 text-sm text-danger" role="alert">
          {validation}
        </p>
      )}
    </form>
  )
}

function addFlow(provider: ProviderDescriptor): {
  heading: string
  steps: ReactNode[]
  submitLabel: string
  submitHint: ReactNode
} {
  if (provider.id === 'gemini-cli') {
    return {
      heading: `Sign in to ${provider.displayName}`,
      steps: [
        <>
          Finish Google sign-in in the browser that opens, then return here.
          This window never takes a password.
        </>,
      ],
      submitLabel: `Sign in to ${provider.displayName}`,
      submitHint:
        'The browser completes Google sign-in. This window never takes a password.',
    }
  }

  return {
    heading: `Sign in to ${provider.displayName}`,
    steps: [],
    submitLabel: `Sign in to ${provider.displayName}`,
    submitHint:
      'The vendor window or terminal completes OAuth. This window never takes a password or token.',
  }
}

/** Matches `account_id_is_safe` plus live on-disk slot reservations. */
const CODEX_LIVE_SLOT_ID = 'codex-cli-on-disk'
const CLAUDE_LIVE_SLOT_ID = 'claude-code-on-disk'

function accountIdProblem(
  accountId: string,
  providerId: string,
): string | null {
  if (accountId === '') {
    return 'Enter an account name.'
  }
  if (!ACCOUNT_ID_PATTERN.test(accountId)) {
    return 'Use only letters, digits, `-` and `_`, at most 128 characters.'
  }
  if (providerId === 'codex-cli' && accountId === CODEX_LIVE_SLOT_ID) {
    return `\`${accountId}\` is reserved for the live on-disk Codex identity; choose a different name.`
  }
  if (providerId === 'claude-code' && accountId === CLAUDE_LIVE_SLOT_ID) {
    return `\`${accountId}\` is reserved for the live on-disk Claude Code identity; choose a different name.`
  }
  return null
}

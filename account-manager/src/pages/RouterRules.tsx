import { useEffect, useState, type FormEvent } from 'react'
import PageHeader from '@/components/PageHeader'
import { listProviders, listRouteRules, replaceRouteRules } from '@/lib/tauri'
import type { ProviderDescriptor, RouteRule } from '@/types'

const inputClass = 'field mt-1'
const buttonClass = 'btn'
const primaryButtonClass = 'btn btn-primary'

interface DraftRule {
  key: number
  matchModel: string
  providerId: string
  targetModel: string
  maxUtilizationPercent: string
}

let nextDraftKey = 0

export default function RouterRules() {
  const [providers, setProviders] = useState<ProviderDescriptor[]>([])
  const [rules, setRules] = useState<DraftRule[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [retryEpoch, setRetryEpoch] = useState(0)
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)
  const [saveStatus, setSaveStatus] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setLoadError(null)

    Promise.all([
      Promise.resolve().then(listProviders),
      Promise.resolve().then(listRouteRules),
    ])
      .then(([nextProviders, nextRules]) => {
        if (cancelled) return
        setProviders(nextProviders)
        setRules(nextRules.map(toDraftRule))
        setSaveError(null)
        setSaveStatus(null)
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setLoadError(String(cause))
      })
      .finally(() => {
        if (cancelled) return
        setLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [retryEpoch])

  function clearSaveMessage() {
    setSaveError(null)
    setSaveStatus(null)
  }

  function updateRule(key: number, update: Partial<DraftRule>) {
    setRules((current) =>
      current.map((rule) => (rule.key === key ? { ...rule, ...update } : rule)),
    )
    clearSaveMessage()
  }

  function moveRule(index: number, offset: -1 | 1) {
    setRules((current) => {
      const target = index + offset
      const moved = current[index]
      if (moved === undefined || target < 0 || target >= current.length) {
        return current
      }
      const reordered = [...current]
      reordered.splice(index, 1)
      reordered.splice(target, 0, moved)
      return reordered
    })
    clearSaveMessage()
  }

  async function saveRules(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const checked = validatedRules(rules, providers)
    if (typeof checked === 'string') {
      setSaveError(checked)
      setSaveStatus(null)
      return
    }

    setSaving(true)
    setSaveError(null)
    setSaveStatus(null)
    try {
      await replaceRouteRules(checked)
      setSaveStatus(
        checked.length === 1
          ? 'Saved 1 routing rule. It will apply when the relay next starts.'
          : `Saved ${checked.length} routing rules. They will apply when the relay next starts.`,
      )
    } catch (cause: unknown) {
      setSaveError(`Could not save routing rules: ${String(cause)}`)
    } finally {
      setSaving(false)
    }
  }

  return (
    <>
      <PageHeader
        title="Router"
        description="Ordered model mappings that select a provider and upstream model."
      />

      <p className="mb-6 text-sm text-ink-muted">
        Rules are tried strictly from top to bottom. There is no default route;
        a request errors when every matching rule is ineligible or no rule
        matches. Saved changes apply when the relay next starts. If it is
        running, stop and start it to apply them.
      </p>

      {loading && (
        <p className="text-sm text-ink-muted" role="status">
          Loading routing rules…
        </p>
      )}

      {!loading && loadError !== null && (
        <div className="space-y-3">
          <p className="notice notice-danger" role="alert">
            Could not load routing rules: {loadError}
          </p>
          <button
            type="button"
            className={buttonClass}
            onClick={() => setRetryEpoch((epoch) => epoch + 1)}
          >
            Retry loading routing rules
          </button>
        </div>
      )}

      {!loading && loadError === null && (
        <form
          aria-busy={saving}
          onSubmit={(event) => {
            void saveRules(event)
          }}
        >
          {rules.length === 0 && (
            <p className="notice notice-warn">
              No routing rules are configured. All requests will error until at
              least one rule is saved.
            </p>
          )}

          <ol className="space-y-4" aria-label="Ordered routing rules">
            {rules.map((rule, index) => {
              const id = `route-rule-${rule.key}`
              return (
                <li key={rule.key}>
                  <fieldset disabled={saving} className="panel p-4">
                    <legend className="px-1 text-sm font-semibold">
                      Rule {index + 1}
                    </legend>

                    <div className="grid gap-4 md:grid-cols-2">
                      <div>
                        <label
                          htmlFor={`${id}-match-model`}
                          className="block text-sm font-medium"
                        >
                          Model pattern
                        </label>
                        <input
                          id={`${id}-match-model`}
                          type="text"
                          value={rule.matchModel}
                          autoComplete="off"
                          spellCheck={false}
                          aria-describedby={`${id}-match-help`}
                          className={inputClass}
                          onChange={(event) =>
                            updateRule(rule.key, {
                              matchModel: event.target.value,
                            })
                          }
                        />
                        <p
                          id={`${id}-match-help`}
                          className="mt-1 text-xs text-ink-muted"
                        >
                          Use an exact name or one trailing{' '}
                          <code className="font-mono">*</code>. Matching is
                          case-sensitive.
                        </p>
                      </div>

                      <div>
                        <label
                          htmlFor={`${id}-provider`}
                          className="block text-sm font-medium"
                        >
                          Provider
                        </label>
                        <select
                          id={`${id}-provider`}
                          value={rule.providerId}
                          className={inputClass}
                          onChange={(event) =>
                            updateRule(rule.key, {
                              providerId: event.target.value,
                            })
                          }
                        >
                          <option value="">Choose a provider</option>
                          {!providers.some(
                            (provider) => provider.id === rule.providerId,
                          ) &&
                            rule.providerId !== '' && (
                              <option value={rule.providerId}>
                                Unavailable provider ({rule.providerId})
                              </option>
                            )}
                          {providers.map((provider) => (
                            <option key={provider.id} value={provider.id}>
                              {provider.displayName}
                            </option>
                          ))}
                        </select>
                      </div>

                      <div>
                        <label
                          htmlFor={`${id}-target-model`}
                          className="block text-sm font-medium"
                        >
                          Upstream model
                        </label>
                        <input
                          id={`${id}-target-model`}
                          type="text"
                          value={rule.targetModel}
                          autoComplete="off"
                          spellCheck={false}
                          className={inputClass}
                          onChange={(event) =>
                            updateRule(rule.key, {
                              targetModel: event.target.value,
                            })
                          }
                        />
                      </div>

                      <div>
                        <label
                          htmlFor={`${id}-max-utilization`}
                          className="block text-sm font-medium"
                        >
                          Maximum utilization (%)
                        </label>
                        <input
                          id={`${id}-max-utilization`}
                          type="number"
                          min="0"
                          max="100"
                          step="any"
                          value={rule.maxUtilizationPercent}
                          aria-describedby={`${id}-quota-help`}
                          className={inputClass}
                          onChange={(event) =>
                            updateRule(rule.key, {
                              maxUtilizationPercent: event.target.value,
                            })
                          }
                        />
                        <p
                          id={`${id}-quota-help`}
                          className="mt-1 text-xs text-ink-muted"
                        >
                          Leave blank to disable the gate. A gated rule is
                          skipped when no numeric quota signal is available.
                        </p>
                      </div>
                    </div>

                    <div className="mt-4 flex flex-wrap gap-2">
                      <button
                        type="button"
                        disabled={index === 0}
                        className={buttonClass}
                        aria-label={`Move rule ${index + 1} up`}
                        onClick={() => moveRule(index, -1)}
                      >
                        Move up
                      </button>
                      <button
                        type="button"
                        disabled={index === rules.length - 1}
                        className={buttonClass}
                        aria-label={`Move rule ${index + 1} down`}
                        onClick={() => moveRule(index, 1)}
                      >
                        Move down
                      </button>
                      <button
                        type="button"
                        className={buttonClass}
                        aria-label={`Remove rule ${index + 1}`}
                        onClick={() => {
                          setRules((current) =>
                            current.filter(
                              (candidate) => candidate.key !== rule.key,
                            ),
                          )
                          clearSaveMessage()
                        }}
                      >
                        Remove
                      </button>
                    </div>
                  </fieldset>
                </li>
              )
            })}
          </ol>

          <div className="mt-4 flex flex-wrap gap-3">
            <button
              type="button"
              disabled={saving}
              className={buttonClass}
              onClick={() => {
                setRules((current) => [...current, emptyDraftRule()])
                clearSaveMessage()
              }}
            >
              Add rule
            </button>
            <button
              type="submit"
              disabled={saving}
              className={primaryButtonClass}
            >
              {saving ? 'Saving…' : 'Save rules'}
            </button>
          </div>

          {saveError !== null && (
            <p className="notice notice-danger mt-4" role="alert">
              {saveError}
            </p>
          )}
          {saveStatus !== null && (
            <p className="mt-4 text-sm text-ink-muted" role="status">
              {saveStatus}
            </p>
          )}
        </form>
      )}
    </>
  )
}

function emptyDraftRule(): DraftRule {
  return {
    key: nextDraftKey++,
    matchModel: '',
    providerId: '',
    targetModel: '',
    maxUtilizationPercent: '',
  }
}

function toDraftRule(rule: RouteRule): DraftRule {
  return {
    key: nextDraftKey++,
    matchModel: rule.matchModel,
    providerId: rule.providerId,
    targetModel: rule.targetModel,
    maxUtilizationPercent:
      rule.maxUtilization === null ? '' : String(rule.maxUtilization * 100),
  }
}

function validatedRules(
  drafts: DraftRule[],
  providers: ProviderDescriptor[],
): RouteRule[] | string {
  const providerIds = new Set(providers.map((provider) => provider.id))
  const rules: RouteRule[] = []

  for (const [index, draft] of drafts.entries()) {
    const position = index + 1
    const matchModel = draft.matchModel.trim()
    const providerId = draft.providerId.trim()
    const targetModel = draft.targetModel.trim()
    const percentText = draft.maxUtilizationPercent.trim()

    if (matchModel === '') return `Rule ${position}: enter a model pattern.`
    const firstStar = matchModel.indexOf('*')
    if (
      firstStar !== -1 &&
      (firstStar !== matchModel.length - 1 ||
        matchModel.lastIndexOf('*') !== firstStar)
    ) {
      return `Rule ${position}: use an exact model name or one trailing *.`
    }
    if (!providerIds.has(providerId)) {
      return `Rule ${position}: choose a registered provider.`
    }
    if (targetModel === '') return `Rule ${position}: enter an upstream model.`

    let maxUtilization: number | null = null
    if (percentText !== '') {
      const percent = Number(percentText)
      if (!Number.isFinite(percent) || percent < 0 || percent > 100) {
        return `Rule ${position}: maximum utilization must be between 0 and 100.`
      }
      maxUtilization = percent / 100
    }

    rules.push({ matchModel, providerId, targetModel, maxUtilization })
  }

  return rules
}

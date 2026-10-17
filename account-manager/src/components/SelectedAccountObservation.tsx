import { useEffect, useRef, useState } from 'react'
import { observeAccount, selectedAccountBinding } from '@/lib/tauri'
import type {
  AccountObserveResult,
  ModelsObservation,
  ObservationOutcome,
  ObservedModel,
  SelectedAccountBinding,
} from '@/types'

function sameBinding(
  a: SelectedAccountBinding,
  b: SelectedAccountBinding,
): boolean {
  return (
    a.providerId === b.providerId &&
    a.accountId === b.accountId &&
    a.accountIncarnation === b.accountIncarnation &&
    a.selectionRevision === b.selectionRevision
  )
}

function modelAccess(
  model: ObservedModel,
  catalog: ModelsObservation,
  binding: SelectedAccountBinding,
): string {
  const source = catalog.provenance
  const supportedEvidence =
    source !== undefined &&
    !source.stale &&
    source.principalBinding !== null &&
    sameBinding(source.principalBinding, binding) &&
    ((source.sourceKind === 'authenticated-catalog' &&
      source.accessBasis === 'confirmed-model-entitlement') ||
      (source.sourceKind === 'productive-execution' &&
        source.accessBasis === 'accepted-productive-execution'))
  if (!supportedEvidence) return 'Access unknown'
  if (model.access === 'available') return 'Available'
  if (model.access === 'unavailable') return 'Unavailable'
  return 'Access unknown'
}

function outcomeLabel(outcome: ObservationOutcome | undefined): string {
  switch (outcome?.kind) {
    case 'observed':
      return 'Metadata observed'
    case 'unavailable':
      return 'Observation unsupported'
    case 'stale':
      return 'Stale'
    case 'failed':
      return 'Observation failed'
    default:
      return 'Unknown'
  }
}

function catalogSource(catalog: ModelsObservation): string {
  switch (catalog.provenance?.sourceKind) {
    case 'managed-home-cache':
      return 'Managed account cache'
    case 'authenticated-catalog':
      return 'Authenticated provider catalog'
    case 'productive-execution':
      return 'Productive task execution'
    default:
      return 'Unknown'
  }
}

/** Refresh only the exact authority selection; selection never proves vendor access. */
export default function SelectedAccountObservation({
  providerId,
  accountId,
  disabled,
}: {
  providerId: string
  accountId: string
  disabled: boolean
}) {
  const [result, setResult] = useState<AccountObserveResult | null>(null)
  const [checking, setChecking] = useState(false)
  const [failed, setFailed] = useState(false)
  const generation = useRef(0)
  const inFlight = useRef(false)

  useEffect(
    () => () => {
      generation.current += 1
    },
    [],
  )

  async function refresh() {
    if (inFlight.current || disabled) return
    inFlight.current = true
    const current = ++generation.current
    setChecking(true)
    setFailed(false)
    setResult(null)
    try {
      const binding = await selectedAccountBinding(providerId)
      if (
        binding === null ||
        binding.providerId !== providerId ||
        binding.accountId !== accountId ||
        binding.accountIncarnation.trim() === '' ||
        !Number.isSafeInteger(binding.selectionRevision)
      )
        throw new Error('Selection unavailable')
      if (generation.current !== current) return
      const observation = await observeAccount({
        binding,
        categories: ['auth', 'models', 'quota'],
      })
      if (generation.current !== current) return
      const selected = await selectedAccountBinding(providerId)
      if (generation.current !== current) return
      if (
        selected === null ||
        !sameBinding(binding, selected) ||
        !sameBinding(binding, observation.binding)
      )
        throw new Error('Selection changed')
      const principal =
        observation.models?.content?.provenance?.principalBinding
      if (
        principal !== undefined &&
        principal !== null &&
        !sameBinding(binding, principal)
      ) {
        throw new Error('Catalog principal changed')
      }
      setResult(observation)
    } catch {
      if (generation.current === current) setFailed(true)
    } finally {
      if (generation.current === current) {
        inFlight.current = false
        setChecking(false)
      }
    }
  }

  const catalog =
    result?.models?.outcome.kind === 'observed'
      ? result.models.content
      : undefined

  return (
    <div className="notice notice-empty mt-3">
      <button
        type="button"
        disabled={disabled || checking}
        onClick={() => {
          void refresh()
        }}
      >
        Check selected account access for {providerId}
      </button>
      <p className="mt-2 text-sm text-ink-muted" role="status">
        {checking
          ? 'Checking the selected account…'
          : failed
            ? 'Selected account access could not be confirmed. Refresh the account list and check again.'
            : result === null
              ? 'Selected account access has not been checked.'
              : `Observed ${accountId} at ${result.observedAt}. Auth: ${outcomeLabel(result.auth?.outcome)}. Models: ${outcomeLabel(result.models?.outcome)}. Quota: ${outcomeLabel(result.quota?.outcome)}.`}
      </p>
      {result !== null && catalog !== undefined && (
        <>
          <p className="mt-2 text-sm text-ink-muted">
            {catalog.provenance?.stale
              ? 'Catalog metadata is stale; model access is unknown.'
              : 'Model advertisement and authentication metadata alone do not establish access.'}
          </p>
          <p className="mt-2 text-sm text-ink-muted">
            Catalog source: {catalogSource(catalog)}.
            {catalog.provenance?.fetchedAt != null &&
              ` Fetched at ${catalog.provenance.fetchedAt}.`}
            {catalog.provenance?.principalBinding == null &&
              ' Source account binding is unknown.'}
          </p>
          <ul className="mt-2 text-sm">
            {catalog.models.map((model) => (
              <li key={model.modelId}>
                {model.modelId}: {modelAccess(model, catalog, result.binding)}
                {model.supportedEfforts !== undefined &&
                  `; efforts: ${model.supportedEfforts.join(', ')}`}
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  )
}

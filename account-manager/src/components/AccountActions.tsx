import { useId, type KeyboardEvent, type ReactNode } from 'react'
import type { Account } from '@/types'

const quietButton = 'btn shrink-0'
const primaryButton = 'btn btn-primary shrink-0'
const dangerButton = 'btn btn-danger shrink-0'

export type PendingKind = 'switch' | 'delete'

/**
 * Per-row selection/switch, launch, and delete, gated by the adapter's
 * capabilities and whether this application holds a usable stored row.
 * Confirm and Cancel sit in a following table row rather than in a dialog so
 * they stay in the tab order without a focus trap (`NFR-6`).
 */
export default function AccountActions({
  account,
  canSwitch,
  canLaunch,
  usesLaunchSelection,
  canDelete,
  forgetsMetadataOnly,
  disabled,
  onRequest,
  onLaunch,
}: {
  account: Account
  canSwitch: boolean
  canLaunch: boolean
  usesLaunchSelection: boolean
  canDelete: boolean
  forgetsMetadataOnly: boolean
  disabled: boolean
  onRequest: (kind: PendingKind) => void
  onLaunch: () => void
}) {
  const name = accountDisplayName(account)

  if (!canSwitch && !canLaunch && !canDelete) {
    return null
  }

  return (
    <div className="flex w-max flex-nowrap items-center gap-2">
      {canSwitch && (
        <button
          type="button"
          disabled={disabled}
          className={quietButton}
          onClick={() => onRequest('switch')}
        >
          {usesLaunchSelection
            ? `Select ${name} for app launch`
            : `Switch to ${name}`}
        </button>
      )}
      {canLaunch && (
        <button
          type="button"
          disabled={disabled}
          className={primaryButton}
          onClick={onLaunch}
        >
          Launch {name}
        </button>
      )}
      {canDelete && (
        <button
          type="button"
          disabled={disabled}
          className={dangerButton}
          onClick={() => onRequest('delete')}
        >
          {forgetsMetadataOnly ? `Forget ${name}` : `Delete ${name}`}
        </button>
      )}
    </div>
  )
}

/**
 * Inline confirm/cancel for a pending switch or delete. Rendered as a
 * full-width row under the account it refers to so the sentence is not
 * squeezed into the actions column.
 */
export function Confirmation({
  id,
  label,
  confirmLabel,
  cancelLabel,
  disabled,
  onCancel,
  onConfirm,
  confirmDanger = false,
  children,
}: {
  id?: string
  label: string
  confirmLabel: string
  cancelLabel: string
  disabled: boolean
  onCancel: () => void
  onConfirm: () => void
  confirmDanger?: boolean
  children: ReactNode
}) {
  const textId = useId()

  function handleKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key === 'Escape') {
      event.preventDefault()
      onCancel()
    }
  }

  return (
    <div
      id={id}
      role="group"
      aria-label={label}
      className="space-y-2"
      onKeyDown={handleKeyDown}
    >
      <p id={textId} className="text-sm text-ink">
        {children}
      </p>
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          autoFocus
          disabled={disabled}
          className={confirmDanger ? dangerButton : primaryButton}
          aria-label={confirmLabel}
          aria-describedby={textId}
          onClick={onConfirm}
        >
          Confirm
        </button>
        <button
          type="button"
          className={quietButton}
          aria-label={cancelLabel}
          onClick={onCancel}
        >
          Cancel
        </button>
      </div>
    </div>
  )
}

export function accountDisplayName(account: Account): string {
  const label = account.label.trim()
  return label === '' ? account.id : label
}

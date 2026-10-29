import { useState } from 'react'
import { useAccountMutation } from '@/lib/accountMutation'
import { launchCancel, launchStatus } from '@/lib/tauri'
import type { LaunchOperationStatus } from '@/types'

export default function LaunchOperations() {
  const { remoteLaunches, updateRemoteLaunch } = useAccountMutation()
  const [pending, setPending] = useState<string | null>(null)
  const [errors, setErrors] = useState<Record<string, string>>({})

  async function refresh(status: LaunchOperationStatus, cancel: boolean) {
    setPending(status.handle)
    try {
      const next = await (cancel ? launchCancel : launchStatus)(status.handle)
      if (next.handle !== status.handle)
        throw new Error('Launch handle mismatch')
      updateRemoteLaunch(next)
      setErrors((current) => ({ ...current, [status.handle]: '' }))
    } catch {
      setErrors((current) => ({
        ...current,
        [status.handle]: cancel
          ? 'Cancellation outcome unconfirmed. The authority retains custody. Check status to recover.'
          : 'Status unavailable. Showing the last confirmed status; the authority retains custody.',
      }))
    } finally {
      setPending(null)
    }
  }

  if (remoteLaunches.length === 0) return null
  return (
    <section aria-label="Authority launches" className="mb-6 space-y-3">
      {remoteLaunches.map((status) => (
        <div key={status.handle} className="notice">
          <p>Launch {status.handle}</p>
          <p role="status">
            Last confirmed status: {status.state}
            {status.processId !== null && ` · PID ${status.processId}`}
            {status.exitCode !== null && ` · Exit ${status.exitCode}`}
            {status.failureCode !== null && ` · ${status.failureCode}`}
          </p>
          <button
            disabled={pending !== null}
            onClick={() => void refresh(status, false)}
          >
            Check launch status
          </button>
          {['starting', 'running', 'cancelling', 'outcome-unknown'].includes(
            status.state,
          ) && (
            <button
              disabled={pending !== null}
              onClick={() => void refresh(status, true)}
            >
              Cancel launch
            </button>
          )}
          {errors[status.handle] && <p role="alert">{errors[status.handle]}</p>}
        </div>
      ))}
    </section>
  )
}

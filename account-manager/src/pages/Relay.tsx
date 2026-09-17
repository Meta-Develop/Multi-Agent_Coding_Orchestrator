import { useEffect, useState } from 'react'
import PageHeader from '@/components/PageHeader'
import { relayStatus, startRelay, stopRelay } from '@/lib/tauri'
import type { RelayStatus } from '@/types'

const primaryButton = 'btn btn-primary'
const dangerButton = 'btn btn-danger'

export default function Relay() {
  const [status, setStatus] = useState<RelayStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [queryEpoch, setQueryEpoch] = useState(0)
  const [pending, setPending] = useState<'start' | 'stop' | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    relayStatus()
      .then((nextStatus) => {
        if (cancelled) return
        setStatus(nextStatus)
        setError(null)
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setError(String(cause))
      })
      .finally(() => {
        if (cancelled) return
        setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [queryEpoch])

  async function setRunning(running: boolean) {
    const action = running ? 'start' : 'stop'
    setPending(action)
    setError(null)
    try {
      setStatus(await (running ? startRelay() : stopRelay()))
    } catch (cause: unknown) {
      setError(String(cause))
      try {
        setStatus(await relayStatus())
      } catch {
        setStatus(null)
      }
    } finally {
      setPending(null)
    }
  }

  return (
    <>
      <PageHeader
        title="Relay"
        description="Local HTTP endpoint that adapts between OpenAI, Anthropic, and Gemini wire formats."
      />
      {loading && (
        <p className="text-sm text-ink-muted" role="status">
          Loading relay state…
        </p>
      )}
      {error !== null && (
        <p className="notice notice-danger mb-4" role="alert">
          Relay operation failed: {error}
        </p>
      )}
      {!loading && status === null && (
        <button
          type="button"
          className={primaryButton}
          onClick={() => {
            setError(null)
            setLoading(true)
            setQueryEpoch((epoch) => epoch + 1)
          }}
        >
          Retry relay status
        </button>
      )}
      {status !== null && (
        <section
          className="panel p-6"
          aria-labelledby="relay-status-heading"
          aria-busy={pending !== null}
        >
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <h2 id="relay-status-heading" className="text-base font-semibold">
                Listener status
              </h2>
              <p className="mt-2 text-sm" aria-live="polite">
                {pending === null ? (
                  <span
                    className={
                      status.running ? 'chip chip-ok' : 'chip chip-muted'
                    }
                  >
                    {status.running ? 'Running' : 'Stopped'}
                  </span>
                ) : (
                  <span className="text-ink-muted">
                    {pending === 'start' ? 'Starting…' : 'Stopping…'}
                  </span>
                )}
              </p>
            </div>
            <button
              type="button"
              disabled={pending !== null}
              className={status.running ? dangerButton : primaryButton}
              onClick={() => {
                void setRunning(!status.running)
              }}
            >
              {pending === 'start'
                ? 'Starting…'
                : pending === 'stop'
                  ? 'Stopping…'
                  : status.running
                    ? 'Stop relay'
                    : 'Start relay'}
            </button>
          </div>

          <dl className="mt-6 grid gap-4 text-sm sm:grid-cols-2">
            <div>
              <dt className="font-medium">Configured address</dt>
              <dd className="mt-1 text-ink-muted">
                <code className="font-mono">{relayOrigin(status)}</code>
              </dd>
            </div>
            <div>
              <dt className="font-medium">Network exposure</dt>
              <dd className="mt-1 text-ink-muted">
                {isLoopback(status.bindAddress)
                  ? 'Loopback only'
                  : 'Non-loopback, authentication required by the relay core'}
              </dd>
            </div>
          </dl>

          <h3 className="mt-6 text-sm font-medium">Configured path prefixes</h3>
          {status.prefixes.length === 0 ? (
            <p className="mt-2 text-sm text-ink-muted">
              No path prefixes are configured.
            </p>
          ) : (
            <ul className="mt-2 space-y-2">
              {status.prefixes.map((prefix) => (
                <li key={prefix}>
                  <code className="font-mono text-sm">{prefix}</code>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}
    </>
  )
}

function relayOrigin(status: RelayStatus): string {
  const host = status.bindAddress.includes(':')
    ? `[${status.bindAddress}]`
    : status.bindAddress
  return `http://${host}:${status.port}`
}

function isLoopback(address: string): boolean {
  return address === '127.0.0.1' || address === '::1'
}

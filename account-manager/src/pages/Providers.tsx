import { useEffect, useState } from 'react'
import InitialMark from '@/components/InitialMark'
import PageHeader from '@/components/PageHeader'
import { listProviders } from '@/lib/tauri'
import type { ProviderDescriptor } from '@/types'

/**
 * The first end-to-end path: React -> Tauri command -> Rust provider registry.
 * If this page renders rows, the IPC surface is wired correctly.
 */
export default function Providers() {
  const [providers, setProviders] = useState<ProviderDescriptor[]>([])
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    listProviders()
      .then(setProviders)
      .catch((cause: unknown) => setError(String(cause)))
  }, [])

  return (
    <>
      <PageHeader
        title="Providers"
        description="Agent tools this application knows how to manage, and whether each was detected on this machine."
      />
      {error !== null && (
        <p className="notice notice-danger mb-4">
          Failed to load providers: {error}
        </p>
      )}
      <div className="table-frame">
        <table className="data-table">
          <thead>
            <tr>
              <th>Provider</th>
              <th>Vendor</th>
              <th>Auth</th>
              <th>Adapter</th>
              <th>Detected</th>
            </tr>
          </thead>
          <tbody>
            {providers.map((provider) => (
              <tr
                key={provider.id}
                data-provider={provider.id}
                className="provider-row"
              >
                <td className="font-medium">
                  <span className="inline-flex items-center gap-2.5">
                    <InitialMark name={provider.displayName} />
                    {provider.displayName}
                    <span className="provider-chip">{provider.vendor}</span>
                  </span>
                </td>
                <td className="text-ink-muted">{provider.vendor}</td>
                <td className="text-ink-muted">
                  {provider.authKinds.join(', ')}
                </td>
                <td className="text-ink-muted">{provider.maturity}</td>
                <td>
                  <span
                    className={
                      provider.installState === 'installed'
                        ? 'chip chip-ok'
                        : provider.installState === 'unknown'
                          ? 'chip chip-warn'
                          : 'chip chip-muted'
                    }
                  >
                    {provider.installState}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}

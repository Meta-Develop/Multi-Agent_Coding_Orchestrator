import PageHeader from '@/components/PageHeader'
import NotImplemented from '@/components/NotImplemented'

export default function Settings() {
  return (
    <>
      <PageHeader
        title="Settings"
        description="Credential storage backend, backup retention, relay binding, and diagnostics."
      />
      <NotImplemented requirement="FR-3">
        Storage backend selection appears once the keychain and encrypted-file
        stores are implemented.
      </NotImplemented>
    </>
  )
}

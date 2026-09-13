import { Outlet } from 'react-router-dom'
import Sidebar from '@/components/Sidebar'
import { AccountMutationProvider, MutationNotice } from '@/lib/accountMutation'

export default function App() {
  return (
    <AccountMutationProvider>
      <div className="flex h-full bg-surface">
        <Sidebar />
        <main className="app-canvas flex-1 overflow-y-auto">
          <div className="app-page">
            <MutationNotice />
            <Outlet />
          </div>
        </main>
      </div>
    </AccountMutationProvider>
  )
}

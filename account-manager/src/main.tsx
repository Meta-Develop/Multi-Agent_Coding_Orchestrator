import { lazy, StrictMode, Suspense, type ReactNode } from 'react'
import { createRoot } from 'react-dom/client'
import { createHashRouter, RouterProvider } from 'react-router-dom'
import App from '@/App'
import '@/index.css'

const Dashboard = lazy(() => import('@/pages/Dashboard'))
const Accounts = lazy(() => import('@/pages/Accounts'))
const Providers = lazy(() => import('@/pages/Providers'))
const Relay = lazy(() => import('@/pages/Relay'))
const RouterRules = lazy(() => import('@/pages/RouterRules'))
const Settings = lazy(() => import('@/pages/Settings'))

function lazyPage(page: ReactNode) {
  return (
    <Suspense
      fallback={
        <p className="text-sm text-ink-muted" role="status">
          Loading…
        </p>
      }
    >
      {page}
    </Suspense>
  )
}

// Hash routing keeps deep links working inside the Tauri webview without a
// server-side rewrite rule.
const router = createHashRouter([
  {
    path: '/',
    element: <App />,
    children: [
      { index: true, element: lazyPage(<Dashboard />) },
      { path: 'accounts', element: lazyPage(<Accounts />) },
      { path: 'providers', element: lazyPage(<Providers />) },
      { path: 'relay', element: lazyPage(<Relay />) },
      { path: 'router', element: lazyPage(<RouterRules />) },
      { path: 'settings', element: lazyPage(<Settings />) },
    ],
  },
])

const container = document.getElementById('root')
if (!container) {
  throw new Error('root container is missing from index.html')
}

createRoot(container).render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>,
)

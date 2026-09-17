import { NavLink } from 'react-router-dom'

const NAV = [
  { to: '/', label: 'Dashboard', end: true, glyph: 'dashboard' },
  { to: '/accounts', label: 'Accounts', end: false, glyph: 'accounts' },
  { to: '/providers', label: 'Providers', end: false, glyph: 'providers' },
  { to: '/relay', label: 'Relay', end: false, glyph: 'relay' },
  { to: '/router', label: 'Router', end: false, glyph: 'router' },
  { to: '/settings', label: 'Settings', end: false, glyph: 'settings' },
] as const

export default function Sidebar() {
  return (
    <nav
      aria-label="Primary"
      className="flex w-56 shrink-0 flex-col border-r border-border-subtle bg-surface-raised"
    >
      <div className="flex items-start gap-2.5 border-b border-border-subtle px-4 py-4">
        <AppMark />
        <div>
          <p className="text-sm leading-5 font-semibold tracking-tight">
            Coding Agent Manager
          </p>
          <p className="mt-0.5 text-xs text-ink-muted">v0.1.0 — pre-alpha</p>
        </div>
      </div>
      <ul className="space-y-0.5 p-3">
        {NAV.map((item) => (
          <li key={item.to}>
            <NavLink
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                [
                  'relative flex items-center gap-2.5 rounded-md py-2 pr-3 pl-3 text-sm',
                  isActive
                    ? 'bg-surface font-medium text-ink'
                    : 'text-ink-muted hover:bg-ink/5 hover:text-ink',
                ].join(' ')
              }
            >
              {({ isActive }) => (
                <>
                  {isActive && (
                    <span
                      aria-hidden="true"
                      className="absolute top-1.5 bottom-1.5 left-0 w-0.5 rounded-full bg-accent"
                    />
                  )}
                  <NavGlyph name={item.glyph} />
                  {item.label}
                </>
              )}
            </NavLink>
          </li>
        ))}
      </ul>
    </nav>
  )
}

function AppMark() {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 24 24"
      className="mt-0.5 h-7 w-7 shrink-0 text-accent"
    >
      <rect
        x="2"
        y="2"
        width="20"
        height="20"
        rx="6"
        fill="currentColor"
        opacity="0.14"
      />
      <path
        d="M8.2 7.6h5a4.2 4.2 0 1 1 0 8.4h-5"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinecap="round"
      />
      <rect
        x="16"
        y="10.6"
        width="3.1"
        height="3.1"
        rx="0.7"
        fill="currentColor"
      />
    </svg>
  )
}

function NavGlyph({ name }: { name: (typeof NAV)[number]['glyph'] }) {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 16 16"
      className="h-4 w-4 shrink-0"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.4"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      {name === 'dashboard' && (
        <>
          <rect x="2" y="2" width="5.2" height="5.2" rx="1" />
          <rect x="8.8" y="2" width="5.2" height="5.2" rx="1" />
          <rect x="2" y="8.8" width="5.2" height="5.2" rx="1" />
          <rect x="8.8" y="8.8" width="5.2" height="5.2" rx="1" />
        </>
      )}
      {name === 'accounts' && (
        <>
          <rect x="2.2" y="3.4" width="8.6" height="5.6" rx="1.1" />
          <rect x="5.2" y="7" width="8.6" height="5.6" rx="1.1" />
        </>
      )}
      {name === 'providers' && (
        <>
          <path d="M8 2.4 13.4 5.4 8 8.4 2.6 5.4Z" />
          <path d="M2.6 8.1 8 11.1l5.4-3" />
          <path d="M2.6 10.8 8 13.8l5.4-3" />
        </>
      )}
      {name === 'relay' && (
        <>
          <path d="M2.4 8h11.2" />
          <path d="M11.2 5.4 13.8 8l-2.6 2.6" />
          <path d="M4.8 5.4 2.2 8l2.6 2.6" />
        </>
      )}
      {name === 'router' && (
        <>
          <path d="M3 12.4 8 3.6l5 8.8" />
          <path d="M5.4 8.4h5.2" />
        </>
      )}
      {name === 'settings' && (
        <>
          <path d="M3 5.2h10" />
          <path d="M3 10.8h10" />
          <circle cx="6.2" cy="5.2" r="1.3" fill="currentColor" stroke="none" />
          <circle
            cx="10.2"
            cy="10.8"
            r="1.3"
            fill="currentColor"
            stroke="none"
          />
        </>
      )}
    </svg>
  )
}

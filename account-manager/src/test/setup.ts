import { cleanup } from '@testing-library/react'
import { afterEach, vi } from 'vitest'
import { invoke } from '@tauri-apps/api/core'
import '@testing-library/jest-dom/vitest'

// Every front-end test must stub `invoke`. A real Tauri runtime, adapter,
// or credential file is never in scope here (NFR-1, docs/TESTING.md §4).
vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(() => {
    throw new Error(
      'invoke is not stubbed; tests must not reach a real Tauri runtime',
    )
  }),
}))

afterEach(() => {
  cleanup()
  vi.mocked(invoke).mockReset()
  vi.mocked(invoke).mockImplementation(() => {
    throw new Error(
      'invoke is not stubbed; tests must not reach a real Tauri runtime',
    )
  })
})

import { AppProvider } from '@/state/AppState'
import DashboardPage from '@/pages/DashboardPage'
import './App.css'

/**
 * Application root.
 *
 * Provides application state to DashboardPage and downstream components.
 */
function App() {
  return (
    <AppProvider>
      <DashboardPage />
    </AppProvider>
  )
}

export default App

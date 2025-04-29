import { useState, useEffect } from 'react'
import './App.css'

function App() {
  const [health, setHealth] = useState<{status: string} | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const checkHealth = async () => {
      try {
        const response = await fetch('/api/health')
        const data = await response.json()
        setHealth(data)
        setError(null)
      } catch (err) {
        setError('Failed to fetch health status')
        setHealth(null)
      }
    }

    checkHealth()
    // Check health status every 30 seconds
    const interval = setInterval(checkHealth, 30000)
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="App">
      <h1>API Health Status</h1>
      {health && (
        <div className="health-status">
          <p>Status: {health.status}</p>
        </div>
      )}
      {error && (
        <div className="error">
          <p>{error}</p>
        </div>
      )}
    </div>
  )
}

export default App

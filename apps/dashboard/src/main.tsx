// Copied from Fermata apps/dashboard/src/main.tsx @ d7cc642 (github.com/bilgin-kocak/fermata, MIT), unchanged.
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { App } from './App.tsx'
import './styles.css'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)

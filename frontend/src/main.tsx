import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import './styles/globals.css'
import Layout from './components/Layout'
import UploadPage from './pages/UploadPage'
import QueuePage from './pages/QueuePage'
import ReportPage from './pages/ReportPage'
import DashboardPage from './pages/DashboardPage'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<UploadPage />} />
          <Route path="/queue" element={<QueuePage />} />
          <Route path="/report/:analysisId" element={<ReportPage />} />
          <Route path="/dashboard" element={<DashboardPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  </React.StrictMode>,
)

import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, QueueItem } from '../lib/api'
import ThreatBadge from '../components/ThreatBadge'

const STATUS_LABEL: Record<string, string> = {
  pending: 'Pending',
  static_running: 'Analyzing — static (…)',
  dynamic_running: 'Analyzing — dynamic (…)',
  reporting: 'Generating report (…)',
  completed: 'Complete',
  error: 'Error',
  rejected: 'Rejected',
}

export default function QueuePage() {
  const [items, setItems] = useState<QueueItem[]>([])
  const [loading, setLoading] = useState(true)

  const load = async () => {
    const data = await api.queue()
    setItems(data)
    setLoading(false)
  }

  useEffect(() => {
    load()
    const interval = setInterval(load, 5000)
    return () => clearInterval(interval)
  }, [])

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight mb-1">Analysis Queue</h1>
          <p className="text-slate-400 text-sm">Recent submissions, refreshed every 5 seconds.</p>
        </div>
        <button className="btn btn-secondary" onClick={load}>Refresh</button>
      </div>

      {loading ? (
        <div className="text-slate-500 text-sm">Loading…</div>
      ) : items.length === 0 ? (
        <div className="card text-center py-16 text-slate-500 text-sm">
          No analyses yet. Upload a sample to get started.
        </div>
      ) : (
        <div className="card p-0 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-base-700/50 text-slate-400 text-xs uppercase tracking-wide">
              <tr>
                <th className="text-left px-5 py-3 font-medium">File</th>
                <th className="text-left px-5 py-3 font-medium">Status</th>
                <th className="text-left px-5 py-3 font-medium">Threat</th>
                <th className="text-left px-5 py-3 font-medium">Submitted</th>
                <th className="px-5 py-3"></th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.analysis_id} className="border-t border-base-600">
                  <td className="px-5 py-3 font-mono text-slate-200">{item.file_name}</td>
                  <td className="px-5 py-3 text-slate-400">{STATUS_LABEL[item.status] ?? item.status}</td>
                  <td className="px-5 py-3"><ThreatBadge level={item.threat_level} /></td>
                  <td className="px-5 py-3 text-slate-500">{new Date(item.created_at).toLocaleString()}</td>
                  <td className="px-5 py-3 text-right">
                    <Link to={`/report/${item.analysis_id}`} className="text-accent hover:underline text-xs font-medium">
                      View Report →
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

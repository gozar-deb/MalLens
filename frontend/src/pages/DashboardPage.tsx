import { useEffect, useState } from 'react'
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip, CartesianGrid } from 'recharts'
import { api, DashboardStats } from '../lib/api'

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null)

  useEffect(() => {
    api.dashboard().then(setStats)
  }, [])

  if (!stats) return <div className="text-slate-500 text-sm">Loading…</div>

  const breakdown = stats.threat_level_breakdown

  return (
    <div>
      <h1 className="text-2xl font-semibold tracking-tight mb-6">Dashboard</h1>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <Stat label="Total Analyses" value={stats.total_analyses} />
        <Stat label="Completed" value={stats.completed} />
        <Stat label="In Progress" value={stats.pending_or_running} />
        <Stat label="High Risk" value={stats.high_risk_count} accent="danger" />
      </div>

      <div className="grid md:grid-cols-2 gap-6 mb-8">
        <div className="card">
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wide mb-4">Submissions (last 14 days)</h2>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={stats.analyses_over_time}>
              <CartesianGrid strokeDasharray="3 3" stroke="#262d38" />
              <XAxis dataKey="date" stroke="#64748b" fontSize={11} />
              <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
              <Tooltip contentStyle={{ background: '#151a21', border: '1px solid #262d38' }} />
              <Bar dataKey="count" fill="#f2b134" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wide mb-4">Threat Level Breakdown</h2>
          <div className="space-y-3">
            {Object.entries(breakdown).map(([level, count]) => (
              <div key={level}>
                <div className="flex justify-between text-sm mb-1">
                  <span className="capitalize text-slate-300">{level}</span>
                  <span className="text-slate-500">{count}</span>
                </div>
                <div className="h-2 bg-base-700 rounded-full overflow-hidden">
                  <div
                    className={`h-full ${level === 'malicious' ? 'bg-danger' : level === 'suspicious' ? 'bg-warn' : level === 'benign' ? 'bg-safe' : 'bg-slate-500'}`}
                    style={{ width: `${stats.total_analyses ? (count / stats.total_analyses) * 100 : 0}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="card p-0 overflow-hidden">
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wide px-5 pt-5 mb-3">Top IOCs</h2>
        <table className="w-full text-sm">
          <thead className="bg-base-700/50 text-slate-400 text-xs uppercase tracking-wide">
            <tr>
              <th className="text-left px-5 py-2 font-medium">Value</th>
              <th className="text-left px-5 py-2 font-medium">Type</th>
              <th className="text-left px-5 py-2 font-medium">Seen</th>
            </tr>
          </thead>
          <tbody>
            {stats.top_iocs.map((ioc, i) => (
              <tr key={i} className="border-t border-base-600">
                <td className="px-5 py-2 font-mono text-slate-200 break-all">{ioc.value}</td>
                <td className="px-5 py-2 text-slate-400">{ioc.type}</td>
                <td className="px-5 py-2 text-slate-500">{ioc.count}×</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function Stat({ label, value, accent }: { label: string; value: number; accent?: string }) {
  return (
    <div className="card">
      <div className="text-xs text-slate-500 mb-1">{label}</div>
      <div className={`text-2xl font-semibold ${accent === 'danger' ? 'text-danger' : 'text-white'}`}>{value}</div>
    </div>
  )
}

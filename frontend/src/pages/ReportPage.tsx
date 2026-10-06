import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { api, FullReport } from '../lib/api'
import ThreatBadge from '../components/ThreatBadge'

const IN_PROGRESS = ['pending', 'static_running', 'dynamic_running', 'reporting']

export default function ReportPage() {
  const { analysisId } = useParams<{ analysisId: string }>()
  const [report, setReport] = useState<FullReport | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!analysisId) return
    let stopped = false

    const load = async () => {
      try {
        const data = await api.report(analysisId)
        if (stopped) return
        setReport(data)
        if (IN_PROGRESS.includes(data.status)) {
          setTimeout(load, 3000)
        }
      } catch (e: any) {
        if (!stopped) setError(e.message)
      }
    }
    load()
    return () => { stopped = true }
  }, [analysisId])

  if (error) {
    return <div className="text-danger text-sm">{error}</div>
  }
  if (!report) {
    return <div className="text-slate-500 text-sm">Loading report…</div>
  }

  const inProgress = IN_PROGRESS.includes(report.status)

  return (
    <div>
      <div className="flex items-start justify-between mb-6 flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight mb-1 font-mono">{report.file_name}</h1>
          <div className="flex items-center gap-3">
            <ThreatBadge level={report.threat_level} />
            <span className="text-slate-400 text-sm">Score {report.threat_score}/100</span>
          </div>
        </div>
        {!inProgress && (
          <div className="flex gap-2">
            <a className="btn btn-secondary" href={api.exportUrl(report.analysis_id, 'html')} target="_blank" rel="noreferrer">HTML</a>
            <a className="btn btn-secondary" href={api.exportUrl(report.analysis_id, 'pdf')}>PDF</a>
            <a className="btn btn-secondary" href={api.exportUrl(report.analysis_id, 'json')}>JSON</a>
          </div>
        )}
      </div>

      {inProgress && (
        <div className="card mb-6 flex items-center gap-3">
          <div className="w-2 h-2 rounded-full bg-accent animate-pulse" />
          <span className="text-sm text-slate-300">
            {{
              pending: 'Queued for analysis…',
              static_running: 'Running static analysis…',
              dynamic_running: 'Running dynamic analysis…',
              reporting: 'Extracting IOCs and generating report…',
            }[report.status]}
          </span>
        </div>
      )}

      {report.report && (
        <div className="card mb-6">
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wide mb-2">Executive Summary</h2>
          <p className="text-slate-300 text-sm leading-relaxed">{report.report.executive_summary}</p>
        </div>
      )}

      {report.static && (
        <div className="card mb-6">
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wide mb-3">Static Analysis</h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <Field label="File type" value={report.static.file_type} />
            <Field label="Entropy" value={report.static.entropy} />
            <Field label="MD5" value={report.static.hash_md5} mono />
            <Field label="SHA256" value={report.static.hash_sha256} mono />
          </div>
          {report.static.yara_matches?.length > 0 && (
            <div className="mt-4">
              <div className="text-xs text-slate-500 mb-2">YARA matches</div>
              <div className="flex flex-wrap gap-2">
                {report.static.yara_matches.map((m: any, i: number) => (
                  <span key={i} className="badge badge-suspicious">{m.rule}</span>
                ))}
              </div>
            </div>
          )}
          {report.static.suspicious_indicators?.length > 0 && (
            <div className="mt-4">
              <div className="text-xs text-slate-500 mb-2">Suspicious API references</div>
              <div className="flex flex-wrap gap-2 font-mono text-xs">
                {report.static.suspicious_indicators.map((s: string) => (
                  <span key={s} className="px-2 py-1 rounded bg-base-700">{s}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {report.dynamic && (
        <div className="card mb-6">
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wide mb-2">Dynamic Analysis</h2>
          <div className="text-sm text-slate-400 mb-2">Provider: <span className="font-mono text-slate-300">{report.dynamic.provider}</span></div>
          {report.dynamic.notes && <p className="text-sm text-slate-400">{report.dynamic.notes}</p>}
        </div>
      )}

      {report.iocs?.length > 0 && (
        <div className="card mb-6 p-0 overflow-hidden">
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wide px-5 pt-5 mb-3">
            Indicators of Compromise ({report.iocs.length})
          </h2>
          <table className="w-full text-sm">
            <thead className="bg-base-700/50 text-slate-400 text-xs uppercase tracking-wide">
              <tr>
                <th className="text-left px-5 py-2 font-medium">Type</th>
                <th className="text-left px-5 py-2 font-medium">Value</th>
                <th className="text-left px-5 py-2 font-medium">Severity</th>
                <th className="text-left px-5 py-2 font-medium">TI Source</th>
              </tr>
            </thead>
            <tbody>
              {report.iocs.map((ioc, i) => (
                <tr key={i} className="border-t border-base-600">
                  <td className="px-5 py-2 text-slate-400">{ioc.ioc_type}</td>
                  <td className="px-5 py-2 font-mono text-slate-200 break-all">{ioc.value}</td>
                  <td className="px-5 py-2">
                    <span className={`badge ${ioc.severity === 'high' ? 'badge-malicious' : ioc.severity === 'medium' ? 'badge-suspicious' : 'badge-unknown'}`}>
                      {ioc.severity}
                    </span>
                  </td>
                  <td className="px-5 py-2 text-slate-500">{ioc.ti_source || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {report.report?.recommendations && (
        <div className="card">
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wide mb-2">Recommendations</h2>
          <p className="text-slate-300 text-sm leading-relaxed">{report.report.recommendations}</p>
        </div>
      )}
    </div>
  )
}

function Field({ label, value, mono }: { label: string; value: any; mono?: boolean }) {
  return (
    <div>
      <div className="text-xs text-slate-500 mb-1">{label}</div>
      <div className={`text-slate-200 break-all ${mono ? 'font-mono text-xs' : ''}`}>{value}</div>
    </div>
  )
}

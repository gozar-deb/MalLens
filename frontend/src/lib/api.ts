const API_BASE = (import.meta as any).env?.VITE_API_BASE_URL || 'http://localhost:8000'

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, options)
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(body.detail || `Request failed (${res.status})`)
  }
  return res.json()
}

export interface UploadResponse {
  analysis_id: string
  file_name: string
  status: string
  message: string
}

export interface StatusResponse {
  analysis_id: string
  file_name: string
  status: string
  threat_level: string
  threat_score: number
  created_at: string
  completed_at: string | null
  error_message: string | null
}

export interface QueueItem {
  analysis_id: string
  file_name: string
  status: string
  threat_level: string
  created_at: string
}

export interface IOC {
  ioc_type: string
  value: string
  context: string | null
  severity: string
  confidence: number
  ti_source: string | null
}

export interface FullReport {
  analysis_id: string
  file_name: string
  status: string
  threat_level: string
  threat_score: number
  created_at: string
  completed_at: string | null
  static: any
  dynamic: any
  iocs: IOC[]
  report: {
    executive_summary: string
    detailed_analysis: string
    recommendations: string
    generated_at: string
    generator: string
  } | null
}

export interface DashboardStats {
  total_analyses: number
  completed: number
  pending_or_running: number
  high_risk_count: number
  threat_level_breakdown: Record<string, number>
  top_iocs: { value: string; type: string; count: number }[]
  analyses_over_time: { date: string; count: number }[]
}

export const api = {
  base: API_BASE,
  upload: (file: File) => {
    const form = new FormData()
    form.append('file', file)
    return request<UploadResponse>('/api/upload', { method: 'POST', body: form })
  },
  status: (id: string) => request<StatusResponse>(`/api/status/${id}`),
  report: (id: string) => request<FullReport>(`/api/report/${id}`),
  queue: () => request<QueueItem[]>('/api/queue'),
  dashboard: () => request<DashboardStats>('/api/dashboard'),
  deleteAnalysis: (id: string) => request(`/api/analysis/${id}`, { method: 'DELETE' }),
  exportUrl: (id: string, format: 'html' | 'pdf' | 'json') =>
    `${API_BASE}/api/report/${id}/export?format=${format}`,
}

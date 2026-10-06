import { useCallback, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../lib/api'

export default function UploadPage() {
  const [dragOver, setDragOver] = useState(false)
  const [file, setFile] = useState<File | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const navigate = useNavigate()

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragOver(false)
    if (e.dataTransfer.files?.[0]) setFile(e.dataTransfer.files[0])
  }, [])

  const submit = async () => {
    if (!file) return
    setBusy(true)
    setError(null)
    try {
      const res = await api.upload(file)
      navigate(`/report/${res.analysis_id}`)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="max-w-2xl mx-auto">
      <div className="mb-8">
        <h1 className="text-2xl font-semibold tracking-tight mb-1">Upload a sample</h1>
        <p className="text-slate-400 text-sm">
          Submit a suspicious file for static and dynamic analysis. Files are never executed on
          the host — everything runs inside an isolated environment.
        </p>
      </div>

      <div
        onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
        onDragLeave={() => setDragOver(false)}
        onDrop={onDrop}
        className={`card border-dashed text-center py-16 transition-colors ${
          dragOver ? 'border-accent bg-accent/5' : ''
        }`}
      >
        <input
          id="file-input"
          type="file"
          className="hidden"
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
        />
        {file ? (
          <div>
            <div className="font-mono text-sm text-slate-200 mb-1">{file.name}</div>
            <div className="text-xs text-slate-500 mb-4">{(file.size / 1024).toFixed(1)} KB</div>
          </div>
        ) : (
          <div className="text-slate-400 mb-4">
            Drag and drop a file here, or
            <label htmlFor="file-input" className="text-accent cursor-pointer ml-1 underline underline-offset-2">
              browse
            </label>
          </div>
        )}
        <button
          className="btn btn-primary disabled:opacity-40 disabled:cursor-not-allowed"
          disabled={!file || busy}
          onClick={submit}
        >
          {busy ? 'Uploading…' : 'Analyze Sample'}
        </button>
      </div>

      {error && (
        <div className="mt-4 text-sm text-danger bg-danger/10 border border-danger/30 rounded-lg px-4 py-3">
          {error}
        </div>
      )}

      <div className="mt-8 text-xs text-slate-500 leading-relaxed">
        Supported types: Windows PE, Linux ELF, Mach-O, PDF, Office documents, common scripts
        (JS/PowerShell/batch), and archives. By uploading, you confirm you have the right to
        submit this file and will use results lawfully.
      </div>
    </div>
  )
}

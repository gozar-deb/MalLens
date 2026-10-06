export default function ThreatBadge({ level }: { level: string }) {
  const cls =
    {
      malicious: 'badge-malicious',
      suspicious: 'badge-suspicious',
      benign: 'badge-benign',
    }[level] || 'badge-unknown'

  return <span className={`badge ${cls}`}>{level}</span>
}

import type { ProbeResponse, ProbeScore } from '../types'

const RESULT_LABEL: Record<ProbeResponse['result'], string> = {
  tripped: 'Probe tripped',
  all_clear: 'All probes cleared',
  gray_zone: 'Probe gray zone — judge ran',
  skipped: 'Probes skipped',
}

const RESULT_TONE: Record<ProbeResponse['result'], string> = {
  tripped: 'bg-red-50 border-red-200 text-red-900',
  all_clear: 'bg-green-50 border-green-200 text-green-900',
  gray_zone: 'bg-amber-50 border-amber-200 text-amber-900',
  skipped: 'bg-gray-50 border-gray-200 text-gray-700',
}

// One horizontal score bar. The fill width is the score; vertical guides mark
// the threshold (deny line) and clear_threshold (allow line). Both come from
// the audit row, NOT the current policy — so historical visualizations stay
// correct after a threshold change.
function ScoreBar({ score, trippedHere }: { score: ProbeScore; trippedHere: boolean }) {
  const pct = Math.max(0, Math.min(1, score.score)) * 100
  const threshPct = Math.max(0, Math.min(1, score.threshold)) * 100
  const clearPct = Math.max(0, Math.min(1, score.clear_threshold)) * 100

  let fillTone = 'bg-amber-300'
  if (trippedHere || score.score >= score.threshold) fillTone = 'bg-red-400'
  else if (score.clear_threshold > 0 && score.score < score.clear_threshold) fillTone = 'bg-green-400'

  return (
    <div className="flex items-center gap-3 text-xs py-1">
      <span className={`font-mono font-semibold w-40 truncate ${trippedHere ? 'text-red-700' : 'text-gray-700'}`} title={score.name}>
        {score.name}
      </span>
      <div className="flex-1 relative h-2 rounded bg-gray-200 overflow-visible">
        <div className={`h-2 rounded ${fillTone}`} style={{ width: `${pct}%` }} />
        {score.clear_threshold > 0 && (
          <div className="absolute top-0 h-2 w-px bg-green-600/70" style={{ left: `${clearPct}%` }} title={`clear ${score.clear_threshold.toFixed(2)}`} />
        )}
        <div className="absolute top-0 h-2 w-px bg-red-600/80" style={{ left: `${threshPct}%` }} title={`deny ${score.threshold.toFixed(2)}`} />
      </div>
      <span className={`font-mono tabular-nums w-12 text-right ${trippedHere ? 'text-red-700 font-semibold' : 'text-gray-600'}`}>
        {score.score.toFixed(3)}
      </span>
      <span className="font-mono text-gray-400 w-32 text-right">
        deny ≥ {score.threshold.toFixed(2)}
        {score.clear_threshold > 0 && <> · allow &lt; {score.clear_threshold.toFixed(2)}</>}
      </span>
    </div>
  )
}

export function ProbeResponseBlock({ probe }: { probe: ProbeResponse }) {
  const tone = RESULT_TONE[probe.result] ?? RESULT_TONE.skipped
  const label = RESULT_LABEL[probe.result] ?? probe.result

  return (
    <div className={`mb-4 p-3 border rounded ${tone}`}>
      <div className="flex items-center gap-2 mb-2">
        <h4 className="text-sm font-semibold">Linear probes</h4>
        <span className="text-xs italic font-normal opacity-80">
          ({label}{probe.duration_ms > 0 && ` · ${probe.duration_ms}ms`})
        </span>
        {probe.tripped && (
          <span className="ml-auto text-xs font-mono font-semibold text-red-800">
            tripped: {probe.tripped}
          </span>
        )}
      </div>
      {probe.skip_reason && (
        <p className="text-xs font-mono mb-2 opacity-80">skip reason: {probe.skip_reason}</p>
      )}
      {probe.scores.length === 0 ? (
        <p className="text-xs italic opacity-70">No scores recorded.</p>
      ) : (
        <div className="space-y-0.5 bg-white/60 rounded p-2">
          {probe.scores.map((s, i) => (
            <ScoreBar key={s.name + i} score={s} trippedHere={probe.tripped === s.name} />
          ))}
        </div>
      )}
    </div>
  )
}

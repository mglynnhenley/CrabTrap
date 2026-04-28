import { useEffect, useMemo, useState } from 'react'
import {
  listPolicyProbes, upsertPolicyProbe, deletePolicyProbe,
  getProbes,
} from '../api/client'
import type { PolicyProbe, UpsertPolicyProbeRequest, Probe } from '../types'

const btnPrimary = 'px-3 py-1.5 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50'
const btnGhost   = 'px-3 py-1.5 text-sm font-medium text-gray-700 bg-white border border-gray-200 rounded-md hover:bg-gray-50 disabled:opacity-50'

// Editable copy of a PolicyProbe row. Numeric fields are strings so the user
// can blank clearThreshold to mean "not set" without fighting type coercion.
// Per-attachment judge override is intentionally absent — gray-zone hits on a
// probe attached to policy A are always adjudicated by policy A.
type Draft = {
  enabled: boolean
  threshold: string
  clearThreshold: string
  aggregation: 'max' | 'mean'
  priority: string
}

function rowToDraft(p: PolicyProbe): Draft {
  return {
    enabled: p.enabled,
    threshold: String(p.threshold),
    clearThreshold: p.clear_threshold == null ? '' : String(p.clear_threshold),
    aggregation: p.aggregation,
    priority: String(p.priority),
  }
}

function draftToRequest(probeName: string, d: Draft): UpsertPolicyProbeRequest | { error: string } {
  const threshold = Number(d.threshold)
  if (!Number.isFinite(threshold) || threshold < 0 || threshold > 1) {
    return { error: 'Threshold must be a number in [0, 1]' }
  }
  let clear: number | null = null
  if (d.clearThreshold.trim() !== '') {
    const v = Number(d.clearThreshold)
    if (!Number.isFinite(v) || v < 0 || v > 1) {
      return { error: 'Clear threshold must be a number in [0, 1]' }
    }
    if (v > threshold) {
      return { error: 'Clear threshold must be <= threshold' }
    }
    clear = v
  }
  const priority = Number(d.priority)
  if (!Number.isFinite(priority) || !Number.isInteger(priority)) {
    return { error: 'Priority must be an integer' }
  }
  return {
    probe_name: probeName,
    enabled: d.enabled,
    threshold,
    clear_threshold: clear,
    aggregation: d.aggregation,
    priority,
    judge_policy_id: null,
  }
}

function PolicyProbeRow({ row, onChanged, onDeleted }: {
  row: PolicyProbe
  onChanged: (next: PolicyProbe) => void
  onDeleted: () => void
}) {
  const [draft, setDraft] = useState<Draft>(() => rowToDraft(row))
  const [saving, setSaving] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => { setDraft(rowToDraft(row)) }, [row])

  const dirty =
    draft.enabled !== row.enabled ||
    Number(draft.threshold) !== row.threshold ||
    (draft.clearThreshold === '' ? row.clear_threshold != null : Number(draft.clearThreshold) !== row.clear_threshold) ||
    draft.aggregation !== row.aggregation ||
    Number(draft.priority) !== row.priority

  const save = async () => {
    const req = draftToRequest(row.probe_name, draft)
    if ('error' in req) {
      setError(req.error)
      return
    }
    setSaving(true)
    setError(null)
    try {
      onChanged(await upsertPolicyProbe(row.policy_id, req))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  // Toggling enabled writes through immediately so the highest-frequency
  // action doesn't require a Save click. Mirrors ProbesPanel's pattern.
  const toggleEnabled = async (next: boolean) => {
    setDraft((d) => ({ ...d, enabled: next }))
    const req = draftToRequest(row.probe_name, { ...draft, enabled: next })
    if ('error' in req) {
      setError(req.error)
      return
    }
    try {
      onChanged(await upsertPolicyProbe(row.policy_id, req))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Toggle failed')
      setDraft(rowToDraft(row))
    }
  }

  const remove = async () => {
    if (!window.confirm(`Detach "${row.probe_name}" from this policy?`)) return
    setDeleting(true)
    try {
      await deletePolicyProbe(row.policy_id, row.probe_name)
      onDeleted()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Delete failed')
      setDeleting(false)
    }
  }

  return (
    <tr className="hover:bg-gray-50">
      <td className="px-4 py-3 font-mono text-xs text-gray-700">{row.probe_name}</td>
      <td className="px-4 py-3">
        <label className="inline-flex items-center cursor-pointer">
          <input
            type="checkbox"
            checked={draft.enabled}
            onChange={(e) => toggleEnabled(e.target.checked)}
            className="sr-only peer"
          />
          <div className="relative w-9 h-5 bg-gray-200 rounded-full peer peer-checked:bg-blue-600 transition-colors">
            <div className={`absolute top-0.5 left-0.5 bg-white w-4 h-4 rounded-full transition-transform ${draft.enabled ? 'translate-x-4' : ''}`} />
          </div>
        </label>
      </td>
      <td className="px-4 py-3">
        <input
          type="number" step="0.01" min="0" max="1"
          value={draft.threshold}
          onChange={(e) => setDraft((d) => ({ ...d, threshold: e.target.value }))}
          className="w-20 px-2 py-1 text-sm border border-gray-200 rounded"
        />
      </td>
      <td className="px-4 py-3">
        <input
          type="number" step="0.01" min="0" max="1" placeholder="—"
          value={draft.clearThreshold}
          onChange={(e) => setDraft((d) => ({ ...d, clearThreshold: e.target.value }))}
          className="w-20 px-2 py-1 text-sm border border-gray-200 rounded"
        />
      </td>
      <td className="px-4 py-3">
        <select
          value={draft.aggregation}
          onChange={(e) => setDraft((d) => ({ ...d, aggregation: e.target.value as 'max' | 'mean' }))}
          className="px-2 py-1 text-sm border border-gray-200 rounded bg-white"
        >
          <option value="max">max</option>
          <option value="mean">mean</option>
        </select>
      </td>
      <td className="px-4 py-3">
        <input
          type="number" step="1"
          value={draft.priority}
          onChange={(e) => setDraft((d) => ({ ...d, priority: e.target.value }))}
          className="w-16 px-2 py-1 text-sm border border-gray-200 rounded"
        />
      </td>
      <td className="px-4 py-3 text-right">
        <div className="flex justify-end gap-2">
          {dirty && (
            <button onClick={save} disabled={saving} className={btnGhost}>
              {saving ? 'Saving…' : 'Save'}
            </button>
          )}
          <button onClick={remove} disabled={deleting} className="text-xs text-red-500 hover:text-red-700 disabled:opacity-30">
            {deleting ? '…' : 'Detach'}
          </button>
        </div>
        {error && <div className="mt-1 text-xs text-red-600">{error}</div>}
      </td>
    </tr>
  )
}

export function PolicyProbesEditor({ policyId }: { policyId: string }) {
  const [rows, setRows] = useState<PolicyProbe[]>([])
  const [catalog, setCatalog] = useState<Probe[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [attachName, setAttachName] = useState('')
  const [attaching, setAttaching] = useState(false)

  const load = async () => {
    try {
      setLoading(true)
      const [rs, cs] = await Promise.all([
        listPolicyProbes(policyId),
        getProbes(),
      ])
      setRows(rs)
      setCatalog(cs)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load policy probes')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [policyId])

  // Catalog rows not yet attached — these populate the "+ attach" picker.
  const unattached = useMemo(() => {
    const taken = new Set(rows.map((r) => r.probe_name))
    return catalog.filter((c) => !taken.has(c.name))
  }, [rows, catalog])

  const attach = async () => {
    if (!attachName) return
    const cataloged = catalog.find((c) => c.name === attachName)
    if (!cataloged) return
    setAttaching(true)
    setError(null)
    try {
      // Seed thresholds from the catalog so admins start from a known
      // baseline. judge_policy_id is intentionally null — gray-zone hits on
      // an attached probe always escalate to *this* policy's prompt.
      const next = await upsertPolicyProbe(policyId, {
        probe_name: cataloged.name,
        enabled: true,
        threshold: cataloged.threshold,
        clear_threshold: cataloged.clear_threshold ?? null,
        aggregation: cataloged.aggregation,
        priority: cataloged.priority,
        judge_policy_id: null,
      })
      setRows((prev) => [...prev, next])
      setAttachName('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Attach failed')
    } finally {
      setAttaching(false)
    }
  }

  const updateRow = (next: PolicyProbe) => {
    setRows((prev) => prev.map((r) => (r.probe_name === next.probe_name ? next : r)))
  }
  const removeRow = (name: string) => {
    setRows((prev) => prev.filter((r) => r.probe_name !== name))
  }

  return (
    <div className="bg-white rounded-xl border border-gray-200 p-5 space-y-3">
      <div>
        <h3 className="text-base font-semibold text-gray-900">Probes (run before this policy)</h3>
        <p className="text-xs text-gray-500 mt-0.5 leading-relaxed">
          Each request hits these probes <em>before</em> the policy prompt runs.
          {' '}A score above <span className="font-mono">threshold</span> denies the request without ever calling the LLM;
          {' '}a score at or below <span className="font-mono">clear</span> approves it.
          {' '}Anything in between falls through to this policy's prompt.
          {' '}With no attachments, requests fall back to the global probe defaults at{' '}
          <span className="font-mono">/probes</span>.
        </p>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg px-3 py-2 text-xs text-red-700">
          {error}
          <button className="ml-3 text-red-500 hover:text-red-700" onClick={() => setError(null)}>&times;</button>
        </div>
      )}

      {loading ? (
        <div className="flex justify-center py-6">
          <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600" />
        </div>
      ) : rows.length === 0 ? (
        <p className="text-xs text-gray-400 italic">
          No probes attached. This policy uses the global defaults.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="text-left px-4 py-2 font-medium text-gray-600">Probe</th>
                <th className="text-left px-4 py-2 font-medium text-gray-600">Enabled</th>
                <th className="text-left px-4 py-2 font-medium text-gray-600">Deny ≥</th>
                <th className="text-left px-4 py-2 font-medium text-gray-600">Allow ≤</th>
                <th className="text-left px-4 py-2 font-medium text-gray-600">Aggregation</th>
                <th className="text-left px-4 py-2 font-medium text-gray-600">Priority</th>
                <th className="px-4 py-2" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {rows.map((r) => (
                <PolicyProbeRow
                  key={r.probe_name}
                  row={r}
                  onChanged={updateRow}
                  onDeleted={() => removeRow(r.probe_name)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {unattached.length > 0 && (
        <div className="flex items-center gap-2 pt-2 border-t border-gray-100">
          <select
            value={attachName}
            onChange={(e) => setAttachName(e.target.value)}
            className="flex-1 px-2 py-1.5 text-sm border border-gray-200 rounded bg-white"
          >
            <option value="">— pick a probe to attach —</option>
            {unattached.map((c) => (
              <option key={c.name} value={c.name}>
                {c.name}{!c.enabled ? ' (catalog disabled)' : ''}
              </option>
            ))}
          </select>
          <button onClick={attach} disabled={!attachName || attaching} className={btnPrimary}>
            {attaching ? 'Attaching…' : 'Attach'}
          </button>
        </div>
      )}
      {!loading && unattached.length === 0 && rows.length > 0 && (
        <p className="text-xs text-gray-400 italic pt-2 border-t border-gray-100">
          All catalog probes are attached.
        </p>
      )}
    </div>
  )
}

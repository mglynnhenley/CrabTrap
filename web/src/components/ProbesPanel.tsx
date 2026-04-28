import { useEffect, useState } from 'react'
import { getProbes, upsertProbe, deleteProbe, discoverProbes, getPolicies } from '../api/client'
import type { Probe, UpsertProbeRequest, LLMPolicy } from '../types'

const btnPrimary = 'px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50'
const btnGhost   = 'px-3 py-1.5 text-sm font-medium text-gray-700 bg-white border border-gray-200 rounded-md hover:bg-gray-50 disabled:opacity-50'

// Editable copy of a Probe row. clear_threshold is stored as a string so the
// user can blank the field to mean "no fast-allow opt-in" without fighting
// the input element's number coercion. judgePolicyId is similarly a string so
// "" can encode "use the request's policy" without a tri-state value.
type Draft = {
  enabled: boolean
  threshold: string
  clearThreshold: string
  aggregation: 'max' | 'mean'
  priority: string
  judgePolicyId: string
}

function probeToDraft(p: Probe): Draft {
  return {
    enabled: p.enabled,
    threshold: String(p.threshold),
    clearThreshold: p.clear_threshold == null ? '' : String(p.clear_threshold),
    aggregation: p.aggregation,
    priority: String(p.priority),
    judgePolicyId: p.judge_policy_id ?? '',
  }
}

function draftToRequest(d: Draft): UpsertProbeRequest | { error: string } {
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
    enabled: d.enabled,
    threshold,
    clear_threshold: clear,
    aggregation: d.aggregation,
    priority,
    judge_policy_id: d.judgePolicyId === '' ? null : d.judgePolicyId,
  }
}

function ProbeRow({ probe, policies, onChanged, onDeleted }: {
  probe: Probe
  policies: LLMPolicy[]
  onChanged: (next: Probe) => void
  onDeleted: () => void
}) {
  const [draft, setDraft] = useState<Draft>(() => probeToDraft(probe))
  const [saving, setSaving] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Re-sync if the parent reloads the list (e.g. after another row's save).
  useEffect(() => { setDraft(probeToDraft(probe)) }, [probe])

  const dirty =
    draft.enabled !== probe.enabled ||
    Number(draft.threshold) !== probe.threshold ||
    (draft.clearThreshold === '' ? probe.clear_threshold != null : Number(draft.clearThreshold) !== probe.clear_threshold) ||
    draft.aggregation !== probe.aggregation ||
    Number(draft.priority) !== probe.priority ||
    draft.judgePolicyId !== (probe.judge_policy_id ?? '')

  const save = async () => {
    const req = draftToRequest(draft)
    if ('error' in req) {
      setError(req.error)
      return
    }
    setSaving(true)
    setError(null)
    try {
      onChanged(await upsertProbe(probe.name, req))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  // Toggling enabled is the highest-frequency action, so write through
  // immediately rather than waiting for the explicit Save click.
  const toggleEnabled = async (next: boolean) => {
    setDraft((d) => ({ ...d, enabled: next }))
    const req = draftToRequest({ ...draft, enabled: next })
    if ('error' in req) {
      setError(req.error)
      return
    }
    try {
      onChanged(await upsertProbe(probe.name, req))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Toggle failed')
      // Revert local state so the UI matches the server.
      setDraft(probeToDraft(probe))
    }
  }

  const remove = async () => {
    if (!window.confirm(`Delete probe "${probe.name}"? This cannot be undone.`)) return
    setDeleting(true)
    try {
      await deleteProbe(probe.name)
      onDeleted()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Delete failed')
      setDeleting(false)
    }
  }

  return (
    <tr className="hover:bg-gray-50">
      <td className="px-4 py-3 font-mono text-xs text-gray-700">{probe.name}</td>
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
          type="number"
          step="0.01"
          min="0"
          max="1"
          value={draft.threshold}
          onChange={(e) => setDraft((d) => ({ ...d, threshold: e.target.value }))}
          className="w-20 px-2 py-1 text-sm border border-gray-200 rounded"
        />
      </td>
      <td className="px-4 py-3">
        <input
          type="number"
          step="0.01"
          min="0"
          max="1"
          placeholder="—"
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
          type="number"
          step="1"
          value={draft.priority}
          onChange={(e) => setDraft((d) => ({ ...d, priority: e.target.value }))}
          className="w-16 px-2 py-1 text-sm border border-gray-200 rounded"
        />
      </td>
      <td className="px-4 py-3">
        <select
          value={draft.judgePolicyId}
          onChange={(e) => setDraft((d) => ({ ...d, judgePolicyId: e.target.value }))}
          className="px-2 py-1 text-sm border border-gray-200 rounded bg-white max-w-[12rem]"
        >
          <option value="">— request policy —</option>
          {policies.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}{p.status === 'draft' ? ' (draft)' : ''}
            </option>
          ))}
        </select>
      </td>
      <td className="px-4 py-3 text-right">
        <div className="flex justify-end gap-2">
          {dirty && (
            <button onClick={save} disabled={saving} className={btnGhost}>
              {saving ? 'Saving…' : 'Save'}
            </button>
          )}
          <button onClick={remove} disabled={deleting} className="text-xs text-red-500 hover:text-red-700 disabled:opacity-30">
            {deleting ? '…' : 'Delete'}
          </button>
        </div>
        {error && <div className="mt-1 text-xs text-red-600">{error}</div>}
      </td>
    </tr>
  )
}

export function ProbesPanel() {
  const [probes, setProbes] = useState<Probe[]>([])
  const [policies, setPolicies] = useState<LLMPolicy[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [discovering, setDiscovering] = useState(false)
  const [discoveryNames, setDiscoveryNames] = useState<string[] | null>(null)
  const [adding, setAdding] = useState<string | null>(null)

  const load = async () => {
    try {
      setLoading(true)
      const [probeRows, policyRows] = await Promise.all([getProbes(), getPolicies()])
      setProbes(probeRows)
      setPolicies(policyRows)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load probes')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const discover = async () => {
    setDiscovering(true)
    setError(null)
    try {
      const { names } = await discoverProbes()
      const known = new Set(probes.map((p) => p.name))
      setDiscoveryNames(names.filter((n) => !known.has(n)))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Discovery failed')
    } finally {
      setDiscovering(false)
    }
  }

  const addProbe = async (name: string) => {
    setAdding(name)
    try {
      await upsertProbe(name, {
        enabled: false,
        threshold: 0.7,
        clear_threshold: null,
        aggregation: 'max',
        priority: probes.length,
        judge_policy_id: null,
      })
      await load()
      setDiscoveryNames((prev) => prev?.filter((n) => n !== name) ?? null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Add failed')
    } finally {
      setAdding(null)
    }
  }

  const updateRow = (next: Probe) => {
    setProbes((prev) => prev.map((p) => (p.name === next.name ? next : p)))
  }
  const removeRow = (name: string) => {
    setProbes((prev) => prev.filter((p) => p.name !== name))
  }

  if (loading) {
    return (
      <div className="flex justify-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-gray-800">Probes</h2>
        <button onClick={discover} disabled={discovering} className={btnPrimary}>
          {discovering ? 'Discovering…' : 'Discover from probe-demo'}
        </button>
      </div>

      <p className="text-sm text-gray-500">
        Probes score request activations and can deny independently of the LLM judge.
        Toggle one to fire on requests; tune <span className="font-mono">threshold</span> to
        change the deny line, or set <span className="font-mono">clear_threshold</span> to
        opt in to the fast-allow path. Aggregation collapses per-token scores.
      </p>

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg px-4 py-3 text-sm text-red-700">
          {error}
          <button className="ml-3 text-red-500 hover:text-red-700" onClick={() => setError(null)}>&times;</button>
        </div>
      )}

      {discoveryNames !== null && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg px-4 py-3 text-sm">
          {discoveryNames.length === 0 ? (
            <span className="text-gray-700">No new probes available — every name returned by probe-demo is already saved.</span>
          ) : (
            <>
              <p className="text-gray-700 mb-2">Found {discoveryNames.length} probe(s) not yet saved:</p>
              <div className="flex flex-wrap gap-2">
                {discoveryNames.map((n) => (
                  <button
                    key={n}
                    onClick={() => addProbe(n)}
                    disabled={adding === n}
                    className="font-mono text-xs px-2 py-1 bg-white border border-blue-300 rounded hover:bg-blue-100 disabled:opacity-50"
                  >
                    {adding === n ? `Adding ${n}…` : `+ ${n}`}
                  </button>
                ))}
              </div>
            </>
          )}
          <button className="mt-2 text-xs text-blue-600 hover:underline" onClick={() => setDiscoveryNames(null)}>Dismiss</button>
        </div>
      )}

      {probes.length === 0 ? (
        <p className="text-gray-500 text-sm bg-white rounded-lg border border-dashed border-gray-200 p-8 text-center">
          No probes saved. Click "Discover" to load names from probe-demo.
        </p>
      ) : (
        <div className="bg-white rounded-xl border border-gray-200 overflow-visible">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="text-left px-4 py-3 font-medium text-gray-600">Name</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">Enabled</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">Threshold</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">Clear</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">Aggregation</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">Priority</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">Judge override</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {probes.map((p) => (
                <ProbeRow
                  key={p.name}
                  probe={p}
                  policies={policies}
                  onChanged={updateRow}
                  onDeleted={() => removeRow(p.name)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

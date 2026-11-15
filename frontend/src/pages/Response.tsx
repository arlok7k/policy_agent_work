import { formatDate, shortId } from '../components/format';
import { Activity, AlertTriangle, RefreshCw, ShieldOff } from 'lucide-react';
import { useState } from 'react';
import type { FormEvent } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import { mapProblem } from '../api/problem';
import type { Problem } from '../api/problem';
import type { Action, CatalogItem, CommandPage, CursorPage, SwitchState } from '../api/types';
import { useCursor } from '../api/useCursor';
import { useGet } from '../api/useGet';
import { useAuth } from '../app/auth-context';
import { Dialog } from '../components/ui/Primitives';
import { Badge, DataState, Empty, PageHeader, Table, Pagination, ProblemNotice } from '../components/PageCommon';

type Decision = { action: Action; operation: 'approve' | 'reject' | 'rollback' };
export function ResponsePage() {
  const { state: auth } = useAuth();
  const principal = auth.status === 'authenticated' ? auth.principal : null;
  const canOperate = principal?.roles.some((role) => role === 'admin' || role === 'senior_analyst') ?? false;
  const cursor = useCursor();
  const [commandHistory, setCommandHistory] = useState<number[]>([]);
  const commandCursor = commandHistory.at(-1);
  const actions = useGet<CursorPage<Action>>(`/response/actions${cursor.cursor ? `?cursor=${encodeURIComponent(cursor.cursor)}` : ''}`);
  const commands = useGet<CommandPage>(`/response/commands${commandCursor ? `?before_id=${commandCursor}` : ''}`);
  const catalog = useGet<{ items: CatalogItem[] }>('/response/catalog');
  const killSwitch = useGet<SwitchState>('/response/kill-switch');
  const [params] = useSearchParams();
  const [incident, setIncident] = useState(params.get('incident') ?? '');
  const [actionType, setActionType] = useState('isolate_host');
  const [mode, setMode] = useState('manual');
  const [agent, setAgent] = useState('');
  const [ip, setIp] = useState('');
  const [targetValue, setTargetValue] = useState('');
  const [message, setMessage] = useState('');
  const [ttl, setTtl] = useState('');
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<Problem | null>(null);
  const [notice, setNotice] = useState('');
  const [decision, setDecision] = useState<Decision | null>(null);
  const [switchConfirm, setSwitchConfirm] = useState(false);
  function refresh() { actions.reload(); commands.reload(); killSwitch.reload(); }
  async function submit(event: FormEvent<HTMLFormElement>, selected: CatalogItem) {
    event.preventDefault(); setBusy(true); setProblem(null); setNotice('');
    const firewallTarget = 'agent_id' in (selected.target_schema.properties ?? {});
    const hasMessage = 'message' in (selected.parameters_schema.properties ?? {});
    const body = {
      incident_id: incident,
      action_type: selected.action_type,
      target: firewallTarget ? { agent_id: agent, ip } : { value: targetValue },
      params: hasMessage ? { message } : {},
      mode: selected.execution_modes.includes(mode) ? mode : selected.execution_modes[0],
      ...(selected.level === 2 && ttl ? { ttl_seconds: Number(ttl) } : {}),
    };
    try {
      const { data } = await api.post<Action>('/response/actions', body);
      setNotice(`Request ${shortId(data.id)} created with status ${data.status.replaceAll('_', ' ')}. Execution is asynchronous and simulated.`);
      cursor.reset(); refresh();
    } catch (error) { setProblem(mapProblem(error)); } finally { setBusy(false); }
  }
  async function decide() {
    if (!decision) return;
    setBusy(true); setProblem(null); setNotice('');
    try {
      await api.post(`/response/actions/${encodeURIComponent(decision.action.id)}/${decision.operation}`, {});
      setNotice(`${decision.operation === 'rollback' ? 'Rollback request' : 'Decision'} recorded. Refresh to check asynchronous execution.`);
      setDecision(null); refresh();
    } catch (error) { setProblem(mapProblem(error)); } finally { setBusy(false); }
  }
  async function toggleSwitch(current: boolean) {
    setBusy(true); setProblem(null); setNotice('');
    try { await api.post('/response/kill-switch', { engaged: !current }); setSwitchConfirm(false); setNotice('Kill Switch state recorded and audited.'); refresh(); }
    catch (error) { setProblem(mapProblem(error)); } finally { setBusy(false); }
  }
  return <div className="page"><PageHeader eyebrow="Operations / Response" title="Response center"
    description="Request simulated containment, review approvals, and monitor executed commands."
    action={<button className="button" onClick={refresh}><RefreshCw size={15} />Refresh activity</button>} />
    <div className="info-banner"><Activity size={17} /><span><strong>Simulation mode.</strong> Connectors record commands but never contact a real endpoint.</span></div>
    {problem && <ProblemNotice problem={problem} />}{notice && <div className="success-notice" role="status">{notice}</div>}
    <div className="response-top-grid">
      <section className="panel"><div className="panel-heading"><div><h2>Request response</h2><p>Choose an action from the host catalog</p></div><span className="subtle-pill">SIMULATED</span></div>
        <DataState state={catalog.state} retry={catalog.reload}>{({ items }) => {
          const requestable = items.filter((item) => item.requestable);
          const selected = requestable.find((item) => item.action_type === actionType) ?? requestable[0];
          if (!selected) return <Empty>No requestable actions are available.</Empty>;
          const firewallTarget = 'agent_id' in (selected.target_schema.properties ?? {});
          const hasMessage = 'message' in (selected.parameters_schema.properties ?? {});
          return <form className="form-grid" onSubmit={(event) => void submit(event, selected)}>
            <label>Incident ID<input required value={incident} onChange={(event) => setIncident(event.target.value)} placeholder="Incident UUID" dir="ltr" /></label>
            <label>Containment / action<select value={selected.action_type} onChange={(event) => { const next = requestable.find((item) => item.action_type === event.target.value); setActionType(event.target.value); setMode(next?.execution_modes[0] ?? 'manual'); }}>
              {requestable.map((item) => <option key={item.action_type} value={item.action_type}>L{item.level} · {item.action_type.replaceAll('_', ' ')}</option>)}</select></label>
            {firewallTarget ? <div className="form-columns"><label>Agent ID<input required value={agent} onChange={(event) => setAgent(event.target.value)} placeholder="e.g. 004" dir="ltr" /></label>
              <label>Target IP<input required value={ip} onChange={(event) => setIp(event.target.value)} placeholder="e.g. 8.8.8.8" dir="ltr" /></label></div>
              : <label>Target value<input required value={targetValue} onChange={(event) => setTargetValue(event.target.value)} /></label>}
            {hasMessage && <label>Message<input required value={message} onChange={(event) => setMessage(event.target.value)} /></label>}
            {selected.level === 2 && <div className="form-columns"><label>Mode<select value={mode} onChange={(event) => setMode(event.target.value)}>{selected.execution_modes.map((item) => <option value={item} key={item}>{item}</option>)}</select></label>
              <label>TTL seconds (optional)<input type="number" min="1" value={ttl} onChange={(event) => setTtl(event.target.value)} placeholder="Server default" /></label></div>}
            <p className="form-hint">{selected.level === 3 ? 'L3 always requires a different senior analyst or admin to approve.' : selected.level === 2 ? 'L2 containment is reversible and uses a bounded TTL.' : 'Execution and availability are enforced by the server.'}</p>
            <button className="button button-primary" disabled={busy}>{busy ? 'Submitting…' : 'Submit response request'}</button>
          </form>;
        }}</DataState>
      </section>
      <section className="panel switch-panel"><div className="panel-heading"><div><h2>Automation Kill Switch</h2><p>Emergency control for automated work</p></div><ShieldOff size={19} className="switch-icon" /></div>
        <DataState state={killSwitch.state} retry={killSwitch.reload}>{(current) => <>
          <div className={`switch-state ${current.engaged ? 'switch-engaged' : ''}`}><div><small>CURRENT STATE</small><strong>{current.engaged ? 'Engaged' : 'Disengaged'}</strong><p>{current.engaged ? 'Automation is paused.' : 'Automation is permitted.'}</p></div><Badge value={current.engaged ? 'engaged' : 'disengaged'} /></div>
          <p className="panel-footnote">The switch pauses automated response and TTL rollback. Human-approved work may continue.</p>
          {canOperate && !switchConfirm && <button className={`button ${current.engaged ? '' : 'button-danger'}`} onClick={() => setSwitchConfirm(true)}>{current.engaged ? 'Disengage Kill Switch' : 'Engage Kill Switch'}</button>}
          {!canOperate && <p className="form-hint">Only a senior analyst or admin can change this control.</p>}
          {switchConfirm && <Dialog open title={current.engaged ? 'Resume automation?' : 'Pause automation?'} onClose={() => setSwitchConfirm(false)}>
            <p>{current.engaged ? 'Queued automated work may resume.' : 'Automated response and TTL rollback will pause; human-approved execution may continue.'}</p>
            <div className="form-actions"><button className="button button-danger" disabled={busy} onClick={() => void toggleSwitch(current.engaged)}>Confirm {current.engaged ? 'disengage' : 'engage'}</button><button className="button" onClick={() => setSwitchConfirm(false)}>Cancel</button></div></Dialog>}
        </>}</DataState>
      </section>
    </div>
    {decision && <Dialog open title={`${decision.operation === 'approve' ? 'Approve' : decision.operation === 'reject' ? 'Reject' : 'Request rollback for'} ${decision.action.action_type.replaceAll('_', ' ')}?`} onClose={() => setDecision(null)}>
      <p>{decision.operation === 'approve' ? 'This records your decision and queues a simulated command. Server safeguards and Four-Eyes still apply.' : decision.operation === 'rollback' ? 'This queues a simulated reversal, subject to safety checks.' : 'This records a rejection; the pending action will not execute.'}</p>
      <div className="form-actions"><button className="button button-primary" disabled={busy} onClick={() => void decide()}>Confirm {decision.operation}</button><button className="button" onClick={() => setDecision(null)}>Cancel</button></div></Dialog>}
    <section className="panel"><div className="panel-heading"><div><h2>Approval queue &amp; actions</h2><p>Actions on this page; pending approvals require a different eligible user</p></div><AlertTriangle size={18} className="text-amber-300" /></div>
      <DataState state={actions.state} retry={actions.reload}>{(page) => <>
        {page.items.length === 0 ? <Empty>No response requests yet.</Empty> : <Table caption="Response activity"><thead><tr><th>Action</th><th>Incident</th><th>Level</th><th>Target</th><th>Status</th><th>Requested</th><th>Controls</th></tr></thead>
          <tbody>{page.items.map((action) => <tr key={action.id}><td><strong>{action.action_type.replaceAll('_', ' ')}</strong><small className="cell-sub">#{shortId(action.id)}</small></td>
            <td><Link className="table-link" to={`/incidents/${encodeURIComponent(action.incident_id)}`}>#{shortId(action.incident_id)}</Link></td><td>L{action.level}</td><td><span dir="ltr">{JSON.stringify(action.target)}</span></td><td><Badge value={action.status} />{action.rollback_request_status && <small className="cell-sub">Rollback: {action.rollback_request_status}</small>}</td><td>{formatDate(action.created_at)}</td>
            <td><div className="table-actions">{canOperate && action.status === 'pending_approval' && action.requested_by !== principal?.id && <><button className="link-action" onClick={() => setDecision({ action, operation: 'approve' })}>Approve</button><button className="link-action" onClick={() => setDecision({ action, operation: 'reject' })}>Reject</button></>}
              {canOperate && action.status === 'executed' && action.rollback_request_status !== 'pending' && catalog.state.status === 'ready' && catalog.state.data.items.some((item) => item.action_type === action.action_type && item.reversible) && <button className="link-action" onClick={() => setDecision({ action, operation: 'rollback' })}>Rollback</button>}</div></td></tr>)}</tbody></Table>}
        <Pagination canPrevious={cursor.canPrevious} canNext={page.next_cursor !== null} previous={cursor.previous} next={() => { if (page.next_cursor) cursor.next(page.next_cursor); }} label="Response action pages" />
      </>}</DataState>
    </section>
    <section className="panel"><div className="panel-heading"><div><h2>Executed-command log</h2><p>Actual connector records, not queued action statuses</p></div><span className="subtle-pill">APPEND ONLY</span></div>
      <DataState state={commands.state} retry={commands.reload}>{(page) => <>
        {page.items.length === 0 ? <Empty>No commands have executed yet.</Empty> : <Table caption="Executed-command log"><thead><tr><th>Command</th><th>Phase</th><th>Target</th><th>Connector</th><th>Mode</th><th>Executed</th></tr></thead>
          <tbody>{page.items.map((command) => <tr key={command.id}><td><strong>{command.command}</strong><small className="cell-sub">Action #{shortId(command.action_id)}</small></td><td>{command.phase}</td><td><span dir="ltr">{JSON.stringify(command.target)}</span></td><td>{command.connector}</td><td>{command.simulated ? 'Simulated' : 'Recorded'}</td><td>{formatDate(command.executed_at)}</td></tr>)}</tbody></Table>}
        <Pagination canPrevious={commandHistory.length > 0} canNext={page.next_before_id !== null} previous={() => setCommandHistory((items) => items.slice(0, -1))}
          next={() => { if (page.next_before_id !== null) setCommandHistory((items) => [...items, page.next_before_id as number]); }} label="Command log pages" />
      </>}</DataState>
    </section>
  </div>;
}

import { formatDate, shortId } from '../components/format';
import { ArrowUpRight, Plus, RefreshCw } from 'lucide-react';
import { useState } from 'react';
import type { FormEvent } from 'react';
import { Link, useParams } from 'react-router-dom';
import { api } from '../api/client';
import { mapProblem } from '../api/problem';
import type { Problem } from '../api/problem';
import type { CursorPage, Evidence, Incident } from '../api/types';
import { useCursor } from '../api/useCursor';
import { useGet } from '../api/useGet';
import { Badge, DataState, Empty, PageHeader, Pagination, ProblemNotice } from '../components/PageCommon';

export function Incidents() {
  const cursor = useCursor();
  const incidents = useGet<CursorPage<Incident>>(`/incidents${cursor.cursor ? `?cursor=${encodeURIComponent(cursor.cursor)}` : ''}`);
  const [showForm, setShowForm] = useState(false);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<Problem | null>(null);
  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setProblem(null);
    try { await api.post('/incidents', { title, description: description || null, alert_ids: [] }); setTitle(''); setDescription(''); setShowForm(false); cursor.reset(); incidents.reload(); }
    catch (error) { setProblem(mapProblem(error)); } finally { setBusy(false); }
  }
  return <div className="page"><PageHeader eyebrow="Workspace / Incidents" title="Incidents" description="Organize investigations and review collected evidence."
    action={<button className="button button-primary" onClick={() => setShowForm(!showForm)}><Plus size={16} />New incident</button>} />
    {problem && <ProblemNotice problem={problem} />}
    {showForm && <section className="panel form-panel"><div className="panel-heading"><div><h2>Create incident</h2><p>Start an investigation without linked alerts.</p></div></div>
      <form className="form-grid" onSubmit={(event) => void create(event)}><label>Title<input required value={title} onChange={(event) => setTitle(event.target.value)} /></label>
        <label>Description<textarea rows={3} value={description} onChange={(event) => setDescription(event.target.value)} /></label>
        <div className="form-actions"><button className="button button-primary" disabled={busy}>{busy ? 'Creating…' : 'Create incident'}</button><button className="button" type="button" onClick={() => setShowForm(false)}>Cancel</button></div></form></section>}
    <section className="panel"><div className="panel-heading"><div><h2>Incident queue</h2><p>Newest investigations first</p></div><button className="button button-quiet" onClick={incidents.reload}><RefreshCw size={14} /> Refresh</button></div>
      <DataState state={incidents.state} retry={incidents.reload}>{(page) => <>
        {page.items.length === 0 ? <Empty>No incidents yet. Investigate an alert or create an incident.</Empty> : <div className="table-wrap"><table><thead><tr><th>Incident</th><th>Status</th><th>Linked alerts</th><th>Created</th><th>Updated</th><th><span className="sr-only">Details</span></th></tr></thead>
          <tbody>{page.items.map((item) => <tr key={item.id}><td><Link className="table-link" to={`/incidents/${encodeURIComponent(item.id)}`}>{item.title}</Link><small className="cell-sub">#{shortId(item.id)}</small></td>
            <td><Badge value={item.status} /></td><td>{item.alert_ids.length}</td><td>{formatDate(item.created_at)}</td><td>{formatDate(item.updated_at)}</td>
            <td><Link className="link-action" aria-label={`View incident ${item.title}`} to={`/incidents/${encodeURIComponent(item.id)}`}><ArrowUpRight size={16} /></Link></td></tr>)}</tbody></table></div>}
        <Pagination canPrevious={cursor.canPrevious} canNext={page.next_cursor !== null} previous={cursor.previous} next={() => { if (page.next_cursor) cursor.next(page.next_cursor); }} label="Incident pages" />
      </>}</DataState></section></div>;
}

export function IncidentDetail() {
  const { id = '' } = useParams();
  const incident = useGet<Incident>(`/incidents/${encodeURIComponent(id)}`);
  const cursor = useCursor();
  const evidence = useGet<CursorPage<Evidence>>(`/incidents/${encodeURIComponent(id)}/evidence${cursor.cursor ? `?cursor=${encodeURIComponent(cursor.cursor)}` : ''}`);
  return <div className="page"><PageHeader eyebrow="Workspace / Incidents" title="Incident details" description="Review linked alerts and evidence for this investigation."
    action={<Link className="button" to="/incidents">Back to incidents</Link>} />
    <DataState state={incident.state} retry={incident.reload}>{(data) => <>
      <section className="panel incident-summary"><div className="panel-heading"><div><h2>{data.title}</h2><p>Incident #{shortId(data.id)} · Created {formatDate(data.created_at)}</p></div><Badge value={data.status} /></div>
        <p className="incident-description">{data.description || 'No description provided.'}</p><div className="panel-actions"><Link className="button button-primary" to={`/response?incident=${encodeURIComponent(data.id)}`}>Request response</Link></div>
        <div className="linked-alerts"><strong>Linked alerts</strong>{data.alert_ids.length ? data.alert_ids.map((alertId) => <Link key={alertId} className="link-action" to={`/alerts/${encodeURIComponent(alertId)}`}>#{shortId(alertId)}</Link>) : <span>None</span>}</div>
      </section>
      <section className="panel"><div className="panel-heading"><div><h2>Evidence</h2><p>Collected during investigations</p></div></div>
        <DataState state={evidence.state} retry={evidence.reload}>{(page) => <>
          {page.items.length === 0 ? <Empty>No evidence has been collected.</Empty> : <div className="evidence-list">{page.items.map((item) => <article className="evidence-item" key={item.id}><div><strong>{item.kind}</strong><small>{formatDate(item.created_at)}</small></div><pre className="code-block" dir="ltr">{JSON.stringify(item.data, null, 2)}</pre></article>)}</div>}
          <Pagination canPrevious={cursor.canPrevious} canNext={page.next_cursor !== null} previous={cursor.previous} next={() => { if (page.next_cursor) cursor.next(page.next_cursor); }} label="Evidence pages" />
        </>}</DataState>
      </section>
    </>}</DataState></div>;
}

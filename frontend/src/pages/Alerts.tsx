import { formatDate, shortId } from '../components/format';
import { ArrowUpRight, RefreshCw, Search } from 'lucide-react';
import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { api } from '../api/client';
import { mapProblem } from '../api/problem';
import type { Problem } from '../api/problem';
import type { Alert, CursorPage, Investigation } from '../api/types';
import { useCursor } from '../api/useCursor';
import { useGet } from '../api/useGet';
import { Badge, DataState, Empty, PageHeader, Table, Pagination, ProblemNotice } from '../components/PageCommon';

export function Alerts() {
  const [severity, setSeverity] = useState('');
  const cursor = useCursor();
  const params = new URLSearchParams();
  if (severity) params.set('severity', severity);
  if (cursor.cursor) params.set('cursor', cursor.cursor);
  const alerts = useGet<CursorPage<Alert>>(`/alerts${params.size ? `?${params}` : ''}`);
  return <div className="page"><PageHeader eyebrow="Workspace / Alerts" title="Alerts" description="Review, investigate, and track incoming security signals."
    action={<button className="button" onClick={alerts.reload}><RefreshCw size={15} /> Refresh</button>} />
    <section className="panel"><div className="panel-heading"><div><h2>Alert feed</h2><p>Newest alerts first</p></div>
      <label className="filter-label">Severity <select value={severity} onChange={(event) => { setSeverity(event.target.value); cursor.reset(); }}>
        <option value="">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label></div>
      <DataState state={alerts.state} retry={alerts.reload}>{(page) => <>
        {page.items.length === 0 ? <Empty>No alerts match this view.</Empty> : <Table caption="Alert feed"><thead><tr><th>Rule / ID</th><th>Source</th><th>Severity</th><th>Agent</th><th>Source IP</th><th>Status</th><th>Received</th><th><span className="sr-only">Details</span></th></tr></thead>
          <tbody>{page.items.map((alert) => <tr key={alert.id}><td><Link className="table-link" to={`/alerts/${encodeURIComponent(alert.id)}`}>{alert.rule_id}</Link><small className="cell-sub">#{shortId(alert.id)}</small></td>
            <td>{alert.source}</td><td><Badge value={alert.severity} /></td><td>{alert.agent ?? '—'}</td><td><span dir="ltr">{alert.src_ip ?? '—'}</span></td><td><Badge value={alert.status} /></td><td>{formatDate(alert.created_at)}</td>
            <td><Link className="link-action" aria-label={`View alert ${alert.rule_id}`} to={`/alerts/${encodeURIComponent(alert.id)}`}><ArrowUpRight size={16} /></Link></td></tr>)}</tbody></Table>}
        <Pagination canPrevious={cursor.canPrevious} canNext={page.next_cursor !== null} previous={cursor.previous} next={() => { if (page.next_cursor) cursor.next(page.next_cursor); }} label="Alert pages" />
      </>}</DataState>
    </section></div>;
}

export function AlertDetail() {
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const alert = useGet<Alert>(`/alerts/${encodeURIComponent(id)}`);
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<Problem | null>(null);
  async function investigate() {
    setBusy(true); setProblem(null);
    try {
      const { data } = await api.post<Investigation>(`/alerts/${encodeURIComponent(id)}/investigate`, {});
      void navigate(`/incidents/${encodeURIComponent(data.incident.id)}`);
    } catch (error) { setProblem(mapProblem(error)); }
    finally { setBusy(false); }
  }
  return <div className="page"><PageHeader eyebrow="Workspace / Alerts" title="Alert details" description="Inspect the source data, then open an investigation."
    action={<Link className="button" to="/alerts">Back to alerts</Link>} />
    {problem && <ProblemNotice problem={problem} />}
    <DataState state={alert.state} retry={alert.reload}>{(data) => <div className="detail-grid">
      <section className="panel"><div className="panel-heading"><div><h2>{data.rule_id}</h2><p>Alert #{shortId(data.id)}</p></div><Badge value={data.severity} /></div>
        <dl className="detail-list"><div><dt>Status</dt><dd><Badge value={data.status} /></dd></div><div><dt>Source</dt><dd>{data.source}</dd></div>
          <div><dt>Agent</dt><dd>{data.agent ?? '—'}</dd></div><div><dt>Source IP</dt><dd dir="ltr">{data.src_ip ?? '—'}</dd></div><div><dt>Destination IP</dt><dd dir="ltr">{data.dst_ip ?? '—'}</dd></div><div><dt>Received</dt><dd>{formatDate(data.created_at)}</dd></div></dl>
        <div className="panel-actions"><button className="button button-primary" onClick={() => void investigate()} disabled={busy}><Search size={16} />{busy ? 'Investigating…' : 'Investigate alert'}</button></div>
      </section>
      <section className="panel"><div className="panel-heading"><div><h2>Raw alert data</h2><p>Untrusted fields are displayed as text</p></div></div><pre className="code-block" dir="ltr">{JSON.stringify(data.raw, null, 2)}</pre></section>
    </div>}</DataState></div>;
}

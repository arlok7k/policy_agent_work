import { formatDate, shortId } from '../components/format';
import { Activity, AlertTriangle, ArrowUpRight, Clock3, ShieldAlert } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import type { Alert, AlertSummary, CursorPage } from '../api/types';
import { useGet } from '../api/useGet';
import { Badge, DataState, Empty, PageHeader } from '../components/PageCommon';

export function Dashboard() {
  const summary = useGet<AlertSummary>('/alerts/stats/summary');
  const alerts = useGet<CursorPage<Alert>>('/alerts');
  return <div className="page dashboard-page">
    <PageHeader eyebrow="Security operations / Overview" title="Operational overview"
      description="A live view of alerts and security activity across your workspace."
      action={<Link className="button button-primary" to="/alerts">View all alerts <ArrowUpRight size={15} /></Link>} />
    <DataState state={summary.state} retry={summary.reload}>{(data) => {
      const severity = Object.entries(data.by_severity).map(([name, count]) => ({ name, count }));
      const total = Object.values(data.by_severity).reduce((a, b) => a + b, 0);
      const high = (data.by_severity.high ?? 0) + (data.by_severity.critical ?? 0);
      const open = data.by_status.open ?? 0;
      return <>
        <div className="metrics-grid">
          <Metric label="Alerts · last 24h" value={data.last_24h} detail="Recently received" icon={<Activity size={18} />} tone="teal" />
          <Metric label="Total alerts" value={total} detail="All recorded alerts" icon={<ShieldAlert size={18} />} tone="blue" />
          <Metric label="High & critical" value={high} detail="Across all alerts" icon={<AlertTriangle size={18} />} tone="red" />
          <Metric label="Open alerts" value={open} detail="Awaiting investigation" icon={<Clock3 size={18} />} tone="amber" />
        </div>
        <div className="dashboard-grid">
          <section className="panel chart-panel"><div className="panel-heading"><div><h2>Severity breakdown</h2><p>All recorded alerts by severity</p></div><span className="subtle-pill">LIVE DATA</span></div>
            {severity.length === 0 ? <Empty>No alert data yet.</Empty> : <div className="chart" role="img" aria-label="Bar chart showing alert counts by severity">
              <ResponsiveContainer width="100%" height="100%"><BarChart data={severity} margin={{ top: 12, right: 12, left: -15, bottom: 0 }}>
                <CartesianGrid stroke="#233549" vertical={false} /><XAxis dataKey="name" tick={{ fill: '#a2b6ca', fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis allowDecimals={false} tick={{ fill: '#8ba2b8', fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: '#122234', border: '1px solid #30485e', borderRadius: 8 }} />
                <Bar dataKey="count" fill="#44d5c0" radius={[4, 4, 0, 0]} maxBarSize={42} />
              </BarChart></ResponsiveContainer></div>}
          </section>
          <section className="panel posture-panel"><div className="panel-heading"><div><h2>Baseline status</h2><p>What is connected in this environment</p></div></div>
            <div className="posture-line"><span className="status-icon">✓</span><span><strong>Host platform</strong><small>Authenticated API session</small></span><Badge value="active" /></div>
            <div className="posture-line"><span className="status-icon status-icon-blue">◈</span><span><strong>Threat intelligence</strong><small>Deterministic mock provider</small></span><span className="subtle-pill">MOCK</span></div>
            <div className="posture-line"><span className="status-icon status-icon-amber">◎</span><span><strong>Response connectors</strong><small>Commands are simulated</small></span><span className="subtle-pill">SIMULATED</span></div>
            <p className="panel-footnote">No real endpoint or intelligence provider is contacted by this baseline.</p>
          </section>
        </div>
      </>;
    }}</DataState>
    <section className="panel latest-panel"><div className="panel-heading"><div><h2>Recent alerts</h2><p>Latest alerts from the host API</p></div><Link className="link-action" to="/alerts">All alerts <ArrowUpRight size={14} /></Link></div>
      <DataState state={alerts.state} retry={alerts.reload}>{(page) => page.items.length === 0 ? <Empty>No alerts have been received yet.</Empty> :
        <div className="table-wrap"><table><thead><tr><th>Alert</th><th>Source</th><th>Severity</th><th>Status</th><th>Received</th><th><span className="sr-only">Details</span></th></tr></thead>
          <tbody>{page.items.slice(0, 6).map((alert) => <tr key={alert.id}><td><Link className="table-link" to={`/alerts/${encodeURIComponent(alert.id)}`}>{alert.rule_id}</Link><small className="cell-sub">#{shortId(alert.id)}</small></td>
            <td>{alert.source}</td><td><Badge value={alert.severity} /></td><td><Badge value={alert.status} /></td><td>{formatDate(alert.created_at)}</td>
            <td><Link className="link-action" aria-label={`View alert ${alert.rule_id}`} to={`/alerts/${encodeURIComponent(alert.id)}`}><ArrowUpRight size={16} /></Link></td></tr>)}</tbody></table></div>}
      </DataState>
    </section>
  </div>;
}
function Metric({ label, value, detail, icon, tone }: { label: string; value: number; detail: string; icon: React.ReactNode; tone: string }) {
  return <section className="metric-card"><div className="metric-top"><span>{label}</span><span className={`metric-icon metric-${tone}`}>{icon}</span></div>
    <strong>{value.toLocaleString()}</strong><small>{detail}</small></section>;
}

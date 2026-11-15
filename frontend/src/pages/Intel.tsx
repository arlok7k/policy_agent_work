import { Radar, Search } from 'lucide-react';
import { useState } from 'react';
import type { FormEvent } from 'react';
import { api } from '../api/client';
import { mapProblem } from '../api/problem';
import type { Problem } from '../api/problem';
import type { CacheStats, IntelResult } from '../api/types';
import { useGet } from '../api/useGet';
import { Badge, DataState, Empty, PageHeader, Table, ProblemNotice } from '../components/PageCommon';

export function Intel({ bulk = false }: { bulk?: boolean }) {
  const stats = useGet<CacheStats>('/threat-intel/cache/stats');
  const [input, setInput] = useState('');
  const [results, setResults] = useState<IntelResult[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<Problem | null>(null);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setProblem(null);
    try {
      if (bulk) {
        const indicators = input.split(/[\s,]+/).filter(Boolean);
        const { data } = await api.post<{ items: IntelResult[] }>('/threat-intel/bulk-check', { indicators });
        setResults(data.items);
      } else {
        const { data } = await api.post<IntelResult>('/threat-intel/check-ip', { indicator: input.trim() });
        setResults([data]);
      }
      stats.reload();
    } catch (error) { setProblem(mapProblem(error)); } finally { setBusy(false); }
  }
  return <div className="page"><PageHeader eyebrow="Intelligence / Workspace" title={bulk ? 'IOC scanner' : 'Threat intelligence'}
    description={bulk ? 'Check a list of IP indicators against the mock provider.' : 'Check an IP indicator and inspect the host intelligence cache.'} />
    <div className="info-banner"><Radar size={17} /><span><strong>Mock provider.</strong> Results are deterministic test data, not real threat intelligence.</span></div>
    {problem && <ProblemNotice problem={problem} />}
    <div className="detail-grid"><section className="panel"><div className="panel-heading"><div><h2>{bulk ? 'Bulk IP check' : 'IP reputation check'}</h2><p>{bulk ? 'Enter IP addresses separated by lines, spaces, or commas' : 'Enter an IPv4 or IPv6 address'}</p></div></div>
      <form className="form-grid" onSubmit={(event) => void submit(event)}><label>{bulk ? 'IP indicators' : 'IP address'}
        {bulk ? <textarea required rows={5} value={input} onChange={(event) => setInput(event.target.value)} dir="ltr" placeholder="8.8.8.8&#10;1.1.1.1" /> : <input required value={input} onChange={(event) => setInput(event.target.value)} dir="ltr" placeholder="8.8.8.8" />}</label>
        <button className="button button-primary" disabled={busy}><Search size={15} />{busy ? 'Checking…' : bulk ? 'Scan indicators' : 'Check IP'}</button></form></section>
      <section className="panel"><div className="panel-heading"><div><h2>Cache status</h2><p>Host cache health and entry counts</p></div></div>
        <DataState state={stats.state} retry={stats.reload}>{(data) => <dl className="detail-list"><div><dt>Fresh entries</dt><dd>{data.fresh}</dd></div><div><dt>Expired entries</dt><dd>{data.expired}</dd></div><div><dt>Redis cache</dt><dd><Badge value={data.redis_available ? 'active' : 'warning'} /></dd></div></dl>}</DataState></section></div>
    <section className="panel"><div className="panel-heading"><div><h2>Results</h2><p>Mock and degraded results are explicitly labelled</p></div></div>
      {results === null || results.length === 0 ? <Empty>No results yet.</Empty> : <Table caption="Intelligence results"><thead><tr><th>Indicator</th><th>Verdict</th><th>Score</th><th>Sources</th><th>Provider</th></tr></thead><tbody>{results.map((item, index) => <tr key={`${item.indicator}-${index}`}>
        <td dir="ltr">{item.indicator}</td><td><Badge value={item.verdict} /></td><td>{item.score ?? '—'}</td><td>{item.sources.join(', ') || '—'}</td><td>{item.mock ? 'Mock' : 'Not mock'}{item.degraded ? ' · degraded' : ''}</td></tr>)}</tbody></Table>}
    </section>
  </div>;
}

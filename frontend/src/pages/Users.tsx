import { formatDate } from '../components/format';
import { Plus, UsersRound } from 'lucide-react';
import { useState } from 'react';
import type { FormEvent } from 'react';
import { api } from '../api/client';
import { mapProblem } from '../api/problem';
import type { Problem } from '../api/problem';
import type { User, UserPage } from '../api/types';
import { useGet } from '../api/useGet';
import { useAuth } from '../app/auth-context';
import { Badge, DataState, Empty, PageHeader, Table, Pagination, ProblemNotice } from '../components/PageCommon';

const roles = ['analyst', 'senior_analyst', 'admin'];
export function UsersPage() {
  const { state: auth } = useAuth();
  const admin = auth.status === 'authenticated' && auth.principal.roles.includes('admin');
  const [offset, setOffset] = useState(0);
  const users = useGet<UserPage>(admin ? `/users?offset=${offset}` : null);
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState<User | null>(null);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('analyst');
  const [active, setActive] = useState(true);
  const [problem, setProblem] = useState<Problem | null>(null);
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  function createForm() { setEditing(null); setUsername(''); setPassword(''); setRole('analyst'); setActive(true); setShowForm(true); setProblem(null); }
  function editForm(user: User) { setEditing(user); setUsername(user.username); setPassword(''); setRole(user.role); setActive(user.is_active); setShowForm(true); setProblem(null); }
  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setProblem(null); setNotice('');
    try {
      if (editing) await api.patch('/users', { id: editing.id, role, is_active: active, ...(password ? { password } : {}) });
      else await api.post('/users', { username, password, role });
      setPassword(''); setShowForm(false); setNotice(editing ? 'User updated and audited.' : 'User created and audited.'); setOffset(0); users.reload();
    } catch (error) { setProblem(mapProblem(error)); } finally { setBusy(false); }
  }
  return <div className="page"><PageHeader eyebrow="Administration / Users" title="Users" description="Manage active users and legacy roles."
    action={admin ? <button className="button button-primary" onClick={createForm}><Plus size={16} />Add user</button> : null} />
    {!admin ? <div className="panel restricted"><UsersRound size={22} /><h2>Administrator access required</h2><p>User management is restricted to administrators.</p></div> : <>
      {problem && <ProblemNotice problem={problem} />}{notice && <div className="success-notice" role="status">{notice}</div>}
      {showForm && <section className="panel form-panel"><div className="panel-heading"><div><h2>{editing ? `Edit ${editing.username}` : 'Create user'}</h2><p>Changes are enforced and audited by the host API.</p></div></div>
        <form className="form-grid" onSubmit={(event) => void save(event)}><div className="form-columns"><label>Username<input required disabled={!!editing} value={username} autoComplete="off" onChange={(event) => setUsername(event.target.value)} /></label>
          <label>Role<select value={role} onChange={(event) => setRole(event.target.value)}>{roles.map((item) => <option key={item} value={item}>{item.replaceAll('_', ' ')}</option>)}</select></label></div>
          <label>{editing ? 'New password (optional)' : 'Password'}<input type="password" required={!editing} autoComplete="new-password" value={password} onChange={(event) => setPassword(event.target.value)} /></label>
          {editing && <label className="checkbox-label"><input type="checkbox" checked={active} onChange={(event) => setActive(event.target.checked)} /> Account active</label>}
          <div className="form-actions"><button className="button button-primary" disabled={busy}>{busy ? 'Saving…' : editing ? 'Save user' : 'Create user'}</button><button className="button" type="button" onClick={() => { setShowForm(false); setPassword(''); }}>Cancel</button></div></form></section>}
      <section className="panel"><div className="panel-heading"><div><h2>User directory</h2><p>Legacy roles are enforced by the backend</p></div></div><DataState state={users.state} retry={users.reload}>{(page) => <>
        {page.items.length === 0 ? <Empty>No users on this page.</Empty> : <Table caption="User directory"><thead><tr><th>Username</th><th>Role</th><th>Status</th><th>Created</th><th>Controls</th></tr></thead><tbody>{page.items.map((user) => <tr key={user.id}>
          <td><strong>{user.username}</strong></td><td>{user.role.replaceAll('_', ' ')}</td><td><Badge value={user.is_active ? 'active' : 'inactive'} /></td><td>{formatDate(user.created_at)}</td><td><button className="link-action" onClick={() => editForm(user)}>Edit<span className="sr-only"> {user.username}</span></button></td></tr>)}</tbody></Table>}
        <Pagination canPrevious={offset > 0} canNext={page.items.length === page.limit} previous={() => setOffset(Math.max(0, offset - page.limit))} next={() => setOffset(offset + page.limit)} label="User pages" />
      </>}</DataState></section>
    </>}</div>;
}

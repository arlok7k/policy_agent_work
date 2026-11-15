import { Save, Settings2 } from 'lucide-react';
import { useState } from 'react';
import type { FormEvent } from 'react';
import { api } from '../api/client';
import { mapProblem } from '../api/problem';
import type { Problem } from '../api/problem';
import type { HostSettings } from '../api/types';
import { useGet } from '../api/useGet';
import { useAuth } from '../app/auth-context';
import { usePresentation } from '../app/presentation-context';
import { DataState, PageHeader, ProblemNotice } from '../components/PageCommon';
import { useI18n } from '../i18n/context';
import { FormField } from '../components/ui/Primitives';
import { useToast } from '../components/ui/toast-context';

export function SettingsPage() {
  const { state: auth } = useAuth();
  const admin = auth.status === 'authenticated' && auth.principal.roles.includes('admin');
  const settings = useGet<HostSettings>(admin ? '/settings' : null);
  return <div className="page"><PageHeader eyebrow="Administration / Settings" title="Settings" description="Manage presentation preferences for this workspace." />
    {!admin ? <div className="panel restricted"><Settings2 size={22} /><h2>Administrator access required</h2><p>Only administrators can view or change workspace settings.</p></div> :
      <DataState state={settings.state} retry={settings.reload}>{(data) => <SettingsForm key={data.updated_at} initial={data} />}</DataState>}
  </div>;
}
function SettingsForm({ initial }: { initial: HostSettings }) {
  const [displayName, setDisplayName] = useState(initial.display_name);
  const [direction, setDefault] = useState(initial.default_direction);
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<Problem | null>(null);
  const notify = useToast();
  const { refreshPresentation } = usePresentation();
  const { setDirection } = useI18n();
  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setProblem(null);
    try {
      const { data } = await api.patch<HostSettings>('/settings', { display_name: displayName, default_direction: direction });
      setDisplayName(data.display_name); setDefault(data.default_direction); setDirection(data.default_direction);
      refreshPresentation(); notify('Presentation settings saved and audited.', 'success');
    } catch (error) { setProblem(mapProblem(error)); } finally { setBusy(false); }
  }
  return <section className="panel settings-panel"><div className="panel-heading"><div><h2>Workspace presentation</h2><p>These settings do not change operational or security policy.</p></div></div>
    {problem && <ProblemNotice problem={problem} />}
    <form className="form-grid" onSubmit={(event) => void save(event)}><FormField id="display-name" label="Display name">{(field) => <input {...field} required value={displayName} onChange={(event) => setDisplayName(event.target.value)} />}</FormField>
      <FormField id="default-direction" label="Default layout direction">{(field) => <select {...field} value={direction} onChange={(event) => setDefault(event.target.value === 'rtl' ? 'rtl' : 'ltr')}><option value="rtl">Right to left</option><option value="ltr">Left to right</option></select>}</FormField>
      <p className="form-hint">Users can override the workspace direction using the layout switch. All settings changes are audited.</p>
      <div><button className="button button-primary" disabled={busy}><Save size={15} />{busy ? 'Saving…' : 'Save settings'}</button></div></form>
  </section>;
}

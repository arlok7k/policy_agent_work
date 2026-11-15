import { ArrowRight, ShieldCheck } from 'lucide-react';
import { useState } from 'react';
import type { FormEvent } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { mapProblem } from '../api/problem';
import { useAuth } from '../app/auth-context';
import { useI18n } from '../i18n/context';

export function Login() {
  const { state, login } = useAuth();
  const { t, direction, setDirection, language, setLanguage } = useI18n();
  const location = useLocation();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const from: unknown = location.state && typeof location.state === 'object' && 'from' in location.state ? location.state.from : '/';
  const destination = typeof from === 'string' && from.startsWith('/') && !from.startsWith('//') && !from.includes('\\') ? from : '/';
  if (state.status === 'authenticated') return <Navigate to={destination} replace />;
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError('');
    try { await login(username, password); setPassword(''); }
    catch (failure) { setError(mapProblem(failure).message); }
    finally { setBusy(false); }
  }
  return <main className="login-screen">
    <div className="login-top"><div className="brand"><span className="brand-mark"><ShieldCheck size={22} /></span>
      <span><strong>SMART <span>SOC</span></strong><small>SECURITY OPERATIONS</small></span></div>
      <div><button className="text-button" onClick={() => setDirection(direction === 'rtl' ? 'ltr' : 'rtl')}
        aria-label={t(direction === 'rtl' ? 'directionLtr' : 'directionRtl')}>{direction === 'rtl' ? 'LTR' : 'RTL'}</button>
      <button className="text-button" onClick={() => setLanguage(language === 'en' ? 'ar' : 'en')} aria-label={t('language')}>
        {language === 'en' ? 'ع' : 'EN'}</button></div></div>
    <div className="login-card"><div className="login-emblem"><ShieldCheck size={26} /></div>
      <p className="eyebrow">{t('secureAccess')}</p><h1>{t('welcome')}</h1><p className="muted">{t('loginIntro')}</p>
      {state.status === 'unavailable' && <p className="form-error" role="alert">{state.problem.message}</p>}
      {error && <p className="form-error" role="alert">{error}</p>}
      <form onSubmit={(event) => void submit(event)} className="login-form">
        <label>{t('username')}<input autoComplete="username" required value={username} onChange={(e) => setUsername(e.target.value)} /></label>
        <label>{t('credentialLabel')}<input type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} /></label>
        <button className="button button-primary login-submit" disabled={busy || state.status === 'loading'}>
          {busy ? t('signingIn') : t('signIn')} <ArrowRight size={17} aria-hidden="true" /></button>
      </form>
      <div className="login-note"><span className="pulse-dot" />{t('baseline')} · {t('simulated')}</div>
    </div>
  </main>;
}

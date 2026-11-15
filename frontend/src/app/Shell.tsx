import { LogOut, Menu, PanelLeftClose, ShieldCheck } from 'lucide-react';
import { useState } from 'react';
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom';
import { mapProblem } from '../api/problem';
import { useI18n } from '../i18n/context';
import { useAuth } from './auth-context';
import { navigation } from './navigation';

export function Shell() {
  const { state, logout } = useAuth();
  const { t, direction, setDirection, language, setLanguage } = useI18n();
  const [open, setOpen] = useState(false);
  const [error, setError] = useState('');
  const location = useLocation();
  const active = navigation.flatMap((group) => group.items)
    .find((item) => item.path === location.pathname || (item.path !== '/' && location.pathname.startsWith(`${item.path}/`)));
  const principal = state.status === 'authenticated' ? state.principal : null;
  async function signOut() {
    try { await logout(); } catch (failure) { setError(mapProblem(failure).message); }
  }
  return (
    <div className="app-shell">
      {open && <button className="sidebar-backdrop" onClick={() => setOpen(false)} aria-label="Close navigation" />}
      <aside className={`sidebar ${open ? 'sidebar-open' : ''}`} aria-label="Primary navigation">
        <Link className="brand" to="/" onClick={() => setOpen(false)}>
          <span className="brand-mark"><ShieldCheck size={22} strokeWidth={2.2} /></span>
          <span><strong>SMART <span>SOC</span></strong><small>SECURITY OPERATIONS</small></span>
        </Link>
        <div className="workspace-label"><span className="workspace-icon"><ShieldCheck size={15} /></span>
          <span><strong>{t('workspace')}</strong><small>{t('baseline')}</small></span><span className="workspace-dot" />
        </div>
        <nav className="nav-scroll">
          {navigation.map((group) => <section className="nav-group" key={group.label}>
            <h2>{t(group.label)}</h2>
            {group.items.map(({ path, label, icon: Icon }) => <NavLink key={path} to={path} end={path === '/'}
              className={({ isActive }) => `nav-link ${isActive ? 'nav-link-active' : ''}`}
              onClick={() => setOpen(false)}><Icon size={17} aria-hidden="true" /><span>{t(label)}</span></NavLink>)}
          </section>)}
        </nav>
        <div className="sidebar-footer"><span className="pulse-dot" />{t('simulated')}</div>
      </aside>
      <div className="shell-body">
        <header className="topbar">
          <div className="topbar-start"><button className="icon-button mobile-menu" onClick={() => setOpen(!open)} aria-label={t('menu')}>
            {open ? <PanelLeftClose size={19} /> : <Menu size={19} />}</button>
            <span className="topbar-kicker">SMART SOC</span><span className="topbar-divider">/</span>
            <span className="topbar-current">{active ? t(active.label) : t('workspace')}</span></div>
          <div className="topbar-actions">
            <span className="environment-pill"><span className="pulse-dot" />{t('baseline')}</span>
            <button className="text-button" onClick={() => setDirection(direction === 'rtl' ? 'ltr' : 'rtl')}
              aria-label={t(direction === 'rtl' ? 'directionLtr' : 'directionRtl')}>{direction === 'rtl' ? 'LTR' : 'RTL'}</button>
            <button className="text-button" onClick={() => setLanguage(language === 'en' ? 'ar' : 'en')}
              aria-label={t('language')}>{language === 'en' ? 'ع' : 'EN'}</button>
            <div className="user-chip"><span className="avatar">{principal?.username?.slice(0, 1).toUpperCase() ?? 'U'}</span>
              <span className="user-details"><strong>{principal?.username}</strong><small>{principal?.roles.join(', ')}</small></span></div>
            <button className="icon-button" aria-label={t('signOut')} title={t('signOut')} onClick={() => void signOut()}><LogOut size={18} /></button>
          </div>
        </header>
        {error && <div role="alert" className="inline-error">{error}</div>}
        <main id="main-content" className="content"><Outlet /></main>
      </div>
    </div>
  );
}

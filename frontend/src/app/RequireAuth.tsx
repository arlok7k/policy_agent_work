import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { useI18n } from '../i18n/context';
import { useAuth } from './auth-context';

export function RequireAuth() {
  const { state, refresh } = useAuth();
  const { t } = useI18n();
  const location = useLocation();
  if (state.status === 'loading') return <main className="status-screen" role="status">{t('sessionCheck')}</main>;
  if (state.status === 'unavailable') return (
    <main className="status-screen" role="alert">
      <h1>{t('unavailable')}</h1><p>{state.problem.message}</p>
      <button className="button button-primary" onClick={() => void refresh()}>{t('retry')}</button>
    </main>
  );
  if (state.status === 'anonymous') return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />;
  return <Outlet />;
}

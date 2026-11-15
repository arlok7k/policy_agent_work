import { Navigate, Route, Routes } from 'react-router-dom';
import { I18nProvider } from '../i18n/I18nProvider';
import { Login } from '../pages/Login';
import { Dashboard } from '../pages/Dashboard';
import { AlertDetail, Alerts } from '../pages/Alerts';
import { IncidentDetail, Incidents } from '../pages/Incidents';
import { ResponsePage } from '../pages/Response';
import { Intel } from '../pages/Intel';
import { SettingsPage } from '../pages/Settings';
import { UsersPage } from '../pages/Users';
import { Placeholder } from '../pages/Placeholder';
import { AuthProvider } from './AuthProvider';
import { ErrorBoundary } from './ErrorBoundary';
import { PresentationProvider } from './PresentationProvider';
import { RequireAuth } from './RequireAuth';
import { Shell } from './Shell';

export function App() {
  return <ErrorBoundary><I18nProvider><AuthProvider><PresentationProvider><Routes>
    <Route path="/login" element={<Login />} />
    <Route element={<RequireAuth />}><Route element={<Shell />}>
      <Route path="/" element={<Dashboard />} />
      <Route path="/alerts" element={<Alerts />} />
      <Route path="/alerts/:id" element={<AlertDetail />} />
      <Route path="/incidents" element={<Incidents />} />
      <Route path="/incidents/:id" element={<IncidentDetail />} />
      <Route path="/response" element={<ResponsePage />} />
      <Route path="/threat-intel" element={<Intel />} />
      <Route path="/ioc-scanner" element={<Intel bulk />} />
      <Route path="/settings" element={<SettingsPage />} />
      <Route path="/users" element={<UsersPage />} />
      <Route path="/mitre" element={<Placeholder title="mitre" />} />
      <Route path="/analytics" element={<Placeholder title="analytics" />} />
      <Route path="/reports" element={<Placeholder title="reports" />} />
      <Route path="/toolkit" element={<Placeholder title="toolkit" />} />
      <Route path="/policies" element={<Placeholder title="policies" policy />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Route></Route>
  </Routes></PresentationProvider></AuthProvider></I18nProvider></ErrorBoundary>;
}

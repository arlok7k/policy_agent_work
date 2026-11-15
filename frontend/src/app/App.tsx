import { Navigate, Route, Routes } from 'react-router-dom';
import { I18nProvider } from '../i18n/I18nProvider';
import { Login } from '../pages/Login';
import { Placeholder } from '../pages/Placeholder';
import { AuthProvider } from './AuthProvider';
import { ErrorBoundary } from './ErrorBoundary';
import { navigation } from './navigation';
import { RequireAuth } from './RequireAuth';
import { Shell } from './Shell';

export function App() {
  return <ErrorBoundary><I18nProvider><AuthProvider><Routes>
    <Route path="/login" element={<Login />} />
    <Route element={<RequireAuth />}><Route element={<Shell />}>
      {navigation.flatMap((group) => group.items).map((item) =>
        <Route key={item.path} path={item.path} element={<Placeholder title={item.label} policy={item.path === '/policies'} />} />)}
      <Route path="/alerts/:id" element={<Placeholder title="alerts" />} />
      <Route path="/incidents/:id" element={<Placeholder title="incidents" />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Route></Route>
  </Routes></AuthProvider></I18nProvider></ErrorBoundary>;
}

import { Activity, BarChart3, BookOpen, Crosshair, FileText, Fingerprint, LayoutDashboard,
  ListChecks, LockKeyhole, Radar, ScanSearch, Settings2, ShieldAlert, ShieldCheck, UsersRound } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import type { MessageKey } from '../i18n/messages';

export interface NavigationItem { path: string; label: MessageKey; icon: LucideIcon }
export interface NavigationGroup { label: MessageKey; items: NavigationItem[] }
export const navigation: NavigationGroup[] = [
  { label: 'workspace', items: [
    { path: '/', label: 'dashboard', icon: LayoutDashboard },
    { path: '/alerts', label: 'alerts', icon: ShieldAlert },
    { path: '/incidents', label: 'incidents', icon: ListChecks },
    { path: '/response', label: 'response', icon: Activity },
  ] },
  { label: 'intelligence', items: [
    { path: '/threat-intel', label: 'threatIntel', icon: Radar },
    { path: '/ioc-scanner', label: 'scanner', icon: ScanSearch },
    { path: '/mitre', label: 'mitre', icon: Crosshair },
    { path: '/analytics', label: 'analytics', icon: BarChart3 },
    { path: '/reports', label: 'reports', icon: FileText },
    { path: '/toolkit', label: 'toolkit', icon: Fingerprint },
  ] },
  { label: 'administration', items: [
    { path: '/settings', label: 'settings', icon: Settings2 },
    { path: '/users', label: 'users', icon: UsersRound },
    { path: '/policies', label: 'policies', icon: BookOpen },
  ] },
];
export { LockKeyhole, ShieldCheck };

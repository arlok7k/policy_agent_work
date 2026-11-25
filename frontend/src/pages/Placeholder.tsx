import { useI18n } from '../i18n/context';
import type { MessageKey } from '../i18n/messages';

export function Placeholder({ title, policy = false }: { title: MessageKey; policy?: boolean }) {
  const { t } = useI18n();
  return <div className="page"><p className="eyebrow">SMART SOC / {t(title)}</p>
    <h1>{t(title)}</h1><p className="muted">{policy ? 'Governance Plane — built in P9' : t('placeholder')}</p></div>;
}

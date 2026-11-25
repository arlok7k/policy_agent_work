export const messages = {
  en: {
    workspace: 'Workspace', operations: 'Operations', intelligence: 'Intelligence', administration: 'Administration',
    dashboard: 'Overview', alerts: 'Alerts', incidents: 'Incidents', response: 'Response',
    threatIntel: 'Threat intelligence', scanner: 'IOC scanner', mitre: 'MITRE ATT&CK',
    analytics: 'Analytics', reports: 'Reports', toolkit: 'Toolkit', settings: 'Settings', users: 'Users', policies: 'Policies',
    signIn: 'Sign in', signingIn: 'Signing in…', username: 'Username', credentialLabel: 'Password',
    signOut: 'Sign out', welcome: 'Welcome back', loginIntro: 'Sign in to your security operations workspace.',
    secureAccess: 'Secure access', baseline: 'Host baseline', simulated: 'Simulated integrations',
    sessionCheck: 'Checking your session…', unavailable: 'Unable to check your session', retry: 'Try again',
    language: 'Change language', directionLtr: 'Switch layout to left-to-right', directionRtl: 'Switch layout to right-to-left',
    menu: 'Toggle navigation', account: 'Account', placeholder: 'Placeholder — this capability is not implemented in the host baseline.',
    notFound: 'Page not found', backHome: 'Return to overview', errorTitle: 'Something went wrong',
  },
  ar: {
    workspace: 'مساحة العمل', operations: 'العمليات', intelligence: 'معلومات التهديدات', administration: 'الإدارة',
    dashboard: 'نظرة عامة', alerts: 'التنبيهات', incidents: 'الحوادث', response: 'الاستجابة',
    threatIntel: 'معلومات التهديدات', scanner: 'فحص المؤشرات', mitre: 'MITRE ATT&CK',
    analytics: 'التحليلات', reports: 'التقارير', toolkit: 'الأدوات', settings: 'الإعدادات', users: 'المستخدمون', policies: 'السياسات',
    signIn: 'تسجيل الدخول', signingIn: 'جارٍ تسجيل الدخول…', username: 'اسم المستخدم', credentialLabel: 'كلمة المرور',
    signOut: 'تسجيل الخروج', welcome: 'مرحباً بعودتك', loginIntro: 'سجّل الدخول إلى مساحة عمليات الأمن.',
    secureAccess: 'وصول آمن', baseline: 'منصة الأساس', simulated: 'تكاملات محاكاة',
    sessionCheck: 'جارٍ التحقق من الجلسة…', unavailable: 'تعذر التحقق من الجلسة', retry: 'حاول مجدداً',
    language: 'تغيير اللغة', directionLtr: 'تغيير الاتجاه إلى اليسار لليمين', directionRtl: 'تغيير الاتجاه إلى اليمين لليسار',
    menu: 'إظهار قائمة التنقل', account: 'الحساب', placeholder: 'عنصر نائب — هذه الوظيفة غير مطبقة في منصة الأساس.',
    notFound: 'الصفحة غير موجودة', backHome: 'العودة إلى النظرة العامة', errorTitle: 'حدث خطأ',
  },
} as const;
export type MessageKey = keyof typeof messages.en;
export type Language = keyof typeof messages;
export type Direction = 'ltr' | 'rtl';

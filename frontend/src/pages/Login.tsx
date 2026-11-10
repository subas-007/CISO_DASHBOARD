import { useSearchParams } from 'react-router-dom';
import { KeyRound, ShieldCheck } from 'lucide-react';
import { useAuth } from '../auth/AuthContext';

const ERRORS: Record<string, string> = {
  no_authorized_role: 'Your account has no role assigned for this application. Contact your administrator.',
  account_disabled: 'Your account has been disabled.',
  invalid_state: 'Your sign-in attempt expired. Please try again.',
  missing_state: 'Your sign-in attempt expired. Please try again.',
  callback_failed: 'Sign-in could not be completed.',
  idp_error: 'The identity provider reported an error.',
};

export function LoginPage() {
  const { login } = useAuth();
  const [params] = useSearchParams();
  const error = params.get('error');

  return (
    <div className="flex min-h-full items-center justify-center bg-[radial-gradient(ellipse_at_top,_#0f2547_0%,_#070b14_60%)] px-4">
      <div className="w-full max-w-md">
        <div className="card p-8">
          <div className="mb-6 flex items-center gap-3">
            <ShieldCheck className="h-10 w-10 text-sky-400" />
            <div>
              <h1 className="text-xl font-semibold text-white">CISO Executive Dashboard</h1>
              <p className="text-sm text-slate-400">Restricted system — authorised personnel only</p>
            </div>
          </div>
          {error && (
            <div className="mb-4 rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-200" role="alert">
              {ERRORS[error] ?? 'Sign-in failed.'}
            </div>
          )}
          <button className="btn-primary w-full py-3" onClick={login}>
            <KeyRound className="h-4 w-4" /> Sign in with corporate SSO
          </button>
          <p className="mt-6 text-xs leading-relaxed text-slate-500">
            Authentication uses OpenID Connect with PKCE and multi-factor authentication enforced by your identity provider.
            All access is logged to an immutable audit trail. Unauthorised use is prohibited and may be subject to disciplinary
            and legal action.
          </p>
        </div>
      </div>
    </div>
  );
}

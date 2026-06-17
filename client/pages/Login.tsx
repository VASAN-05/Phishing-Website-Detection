import { useState, type FormEvent } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { ArrowRight, Fingerprint, LockKeyhole, Sparkles } from "lucide-react";
import ATLLogo from "@/components/ATLLogo";

const AUTH_KEY = "atl-authenticated";
export default function Login() {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [rememberMe, setRememberMe] = useState(true);
  const [signedIn, setSignedIn] = useState(
    window.localStorage.getItem(AUTH_KEY) === "true",
  );

  if (signedIn) {
    return <Navigate to="/" replace />;
  }

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (!email.trim() || !password.trim()) {
      return;
    }

    window.localStorage.setItem(AUTH_KEY, rememberMe ? "true" : "session");
    setSignedIn(true);
    navigate("/", { replace: true });
  };

  return (
    <main className="min-h-screen px-4 py-6 md:px-6 md:py-8">
      <div className="mx-auto flex min-h-[calc(100vh-3rem)] w-full max-w-6xl flex-col overflow-hidden rounded-[30px] border border-white/10 bg-[var(--atl-surface)] shadow-[0_24px_80px_rgba(0,0,0,0.35)] backdrop-blur-xl md:flex-row">
        <section className="relative flex w-full flex-col items-center justify-center gap-10 overflow-hidden px-6 py-8 text-center md:w-[44%] md:px-10 md:py-10">
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_left,rgba(66,133,244,0.25),transparent_38%),radial-gradient(circle_at_bottom_right,rgba(49,110,241,0.18),transparent_34%)]" />
          <div className="relative z-10 flex items-center justify-center">
            <div className="flex items-center gap-3">
              <ATLLogo className="h-10 w-10" withShield />
              <div>
                <p className="text-xs uppercase tracking-[0.32em] text-white/55">Welcome back</p>
                <h1 className="text-2xl font-black tracking-tight text-[var(--atl-text)]">ATL Security</h1>
              </div>
            </div>
          </div>

          <div className="relative z-10 max-w-md space-y-5">
            <p className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/8 px-3 py-1 text-xs font-semibold text-white/70">
              <Sparkles className="h-3.5 w-3.5 text-[#4ea1ff]" />
              Secure access to your dashboard
            </p>
            <h2 className="max-w-md text-4xl font-black leading-[1.02] tracking-tight text-[var(--atl-text)] md:text-5xl">
              Sign in to scan, protect, and manage your profile.
            </h2>
            <p className="max-w-md text-sm leading-6 text-[var(--atl-muted)] md:text-base">
              Analyse suspicious files, domains and URLs to detect malware and other breaches,
              automatically share with the security community.
            </p>
          </div>
        </section>

        <section className="flex w-full items-center justify-center px-4 py-8 md:w-[56%] md:px-10">
          <form
            onSubmit={handleSubmit}
            className="w-full max-w-md rounded-[28px] border border-white/10 bg-[var(--atl-panel-strong)] p-6 shadow-[0_20px_60px_rgba(0,0,0,0.28)] md:p-8"
          >
            <div className="mb-8 space-y-2">
              <p className="text-xs font-semibold uppercase tracking-[0.28em] text-white/40">
                Login Page
              </p>
              <h3 className="text-3xl font-black tracking-tight text-white">Sign in</h3>
              <p className="text-sm text-white/55">
                Enter any email and password to open the dashboard in this demo build.
              </p>
            </div>

            <div className="space-y-5">
              <label className="block">
                <span className="mb-2 block text-xs font-semibold uppercase tracking-[0.2em] text-white/50">
                  Email
                </span>
                <div className="flex items-center gap-3 rounded-2xl border border-white/10 bg-white/8 px-4 py-3.5">
                  <Fingerprint className="h-4 w-4 shrink-0 text-white/40" />
                  <input
                    value={email}
                    onChange={(event) => setEmail(event.target.value)}
                    placeholder="you@example.com"
                    type="email"
                    className="w-full bg-transparent text-sm text-white outline-none placeholder:text-white/35"
                    autoComplete="email"
                  />
                </div>
              </label>

              <label className="block">
                <span className="mb-2 block text-xs font-semibold uppercase tracking-[0.2em] text-white/50">
                  Password
                </span>
                <div className="flex items-center gap-3 rounded-2xl border border-white/10 bg-white/8 px-4 py-3.5">
                  <LockKeyhole className="h-4 w-4 shrink-0 text-white/40" />
                  <input
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    placeholder="Enter password"
                    type="password"
                    className="w-full bg-transparent text-sm text-white outline-none placeholder:text-white/35"
                    autoComplete="current-password"
                  />
                </div>
              </label>
            </div>

            <div className="mt-4 flex items-center justify-between gap-3 text-sm text-white/60">
              <label className="flex items-center gap-2">
                <input
                  checked={rememberMe}
                  onChange={(event) => setRememberMe(event.target.checked)}
                  type="checkbox"
                  className="h-4 w-4 rounded border-white/20 bg-transparent text-[#4285f4] focus:ring-[#4285f4]"
                />
                Remember me
              </label>
              <span className="text-xs text-white/35">Profile, theme, and sign-out are saved locally</span>
            </div>

            <button
              type="submit"
              className="mt-6 flex h-12 w-full items-center justify-center gap-2 rounded-2xl bg-[#4285f4] text-sm font-semibold text-white transition hover:brightness-110"
            >
              Sign in
              <ArrowRight className="h-4 w-4" />
            </button>

            <div className="mt-5 rounded-2xl border border-white/10 bg-white/8 px-4 py-4 text-sm text-white/70">
              <p className="font-semibold text-white">Tip</p>
              <p className="mt-1 leading-6">
                If you want the session to end, use the sign-out option in the profile menu.
              </p>
            </div>
          </form>
        </section>
      </div>
    </main>
  );
}

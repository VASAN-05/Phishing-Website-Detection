import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { LogOut, MoonStar, SunMedium } from "lucide-react";
import ATLLogo from "./ATLLogo";
import type { Profile } from "@/pages/Index";
import { applyTheme, useTheme } from "@/hooks/use-theme";

export const NOTIF_KEY = "atl-notifications-enabled";

const AUTH_KEY = "atl-authenticated";
type NavbarProps = {
  profileOpen: boolean;
  setProfileOpen: (open: boolean) => void;
  savedProfile?: Profile;
  avatarPreview?: string;
};

export default function Navbar({
  profileOpen,
  setProfileOpen,
  savedProfile,
  avatarPreview,
}: NavbarProps) {
  const [searchValue, setSearchValue] = useState("");
  const [notifOpen, setNotifOpen] = useState(false);
  const [profileMenuOpen, setProfileMenuOpen] = useState(false);
  const theme = useTheme();
  const [notifEnabled, setNotifEnabled] = useState<boolean>(() => {
    try {
      return JSON.parse(localStorage.getItem(NOTIF_KEY) ?? "true");
    } catch {
      return true;
    }
  });
  const notifRef = useRef<HTMLDivElement>(null);
  const profileMenuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    localStorage.setItem(NOTIF_KEY, JSON.stringify(notifEnabled));
  }, [notifEnabled]);

  useEffect(() => {
    const h = (e: MouseEvent) => {
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) {
        setNotifOpen(false);
      }
      if (profileMenuRef.current && !profileMenuRef.current.contains(e.target as Node)) {
        setProfileMenuOpen(false);
      }
    };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, []);

  const initials = savedProfile?.name
    ? savedProfile.name.trim().split(" ").map((w) => w[0]).join("").toUpperCase().slice(0, 2)
    : "";

  const toggleTheme = () => {
    applyTheme(theme === "dark" ? "light" : "dark");
  };

  const handleSignOut = () => {
    window.localStorage.removeItem(AUTH_KEY);
    setProfileMenuOpen(false);
    setProfileOpen(false);
    window.location.assign("/login");
  };

  return (
    <header className="w-full">
      <nav
        className="flex h-[70px] items-center gap-3 px-4 md:h-[81px] md:gap-5 md:px-8 lg:px-16"
        style={{ background: "var(--atl-page-bg-alt)" }}
      >
        <Link to="/" className="flex shrink-0 items-center gap-2">
          <ATLLogo className="h-7 w-8 md:h-9 md:w-10" />
          <span className="text-2xl font-bold leading-none text-[var(--atl-text)] md:text-4xl">
            ATL
          </span>
        </Link>

        <div className="mx-2 min-w-0 flex-1 md:mx-4">
          <input
            type="text"
            placeholder="URL, File, or Domain"
            value={searchValue}
            onChange={(e) => setSearchValue(e.target.value)}
            className={`w-full rounded-full text-base font-normal outline-none transition-all md:text-lg ${
              theme === "light" ? "placeholder:text-slate-500" : "placeholder:text-white/35"
            }`}
            style={{
              background: "var(--atl-surface-strong)",
              border: "2.5px solid var(--atl-border)",
              padding: "9px 22px",
              color: "var(--atl-text)",
              caretColor: "var(--atl-text)",
            }}
          />
        </div>

        <div className="flex shrink-0 items-center gap-3 md:gap-4">
          <button
            type="button"
            onClick={toggleTheme}
            className="flex h-10 w-10 items-center justify-center rounded-full border border-white/10 bg-white/5 text-[var(--atl-text)] transition hover:scale-105 hover:bg-white/10"
            aria-label="Toggle theme"
          >
            {theme === "dark" ? <SunMedium className="h-5 w-5" /> : <MoonStar className="h-5 w-5" />}
          </button>

          <div className="relative" ref={notifRef}>
            <button
              onClick={() => setNotifOpen((v) => !v)}
              className="relative transition-opacity hover:opacity-75"
              aria-label="Notifications"
              aria-expanded={notifOpen}
            >
              <svg
                width="28"
                height="28"
                viewBox="0 0 24 24"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
                className="h-6 w-6 md:h-7 md:w-7"
              >
                <path
                  d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"
                  stroke={notifEnabled ? (theme === "light" ? "#1f2937" : "white") : "#555"}
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
                <path
                  d="M13.73 21a2 2 0 0 1-3.46 0"
                  stroke={notifEnabled ? (theme === "light" ? "#1f2937" : "white") : "#555"}
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
                {!notifEnabled && (
                  <line
                    x1="3"
                    y1="3"
                    x2="21"
                    y2="21"
                    stroke="#ef4444"
                    strokeWidth="2"
                    strokeLinecap="round"
                  />
                )}
              </svg>
              {notifEnabled && (
                <span
                  className="absolute -right-0.5 -top-0.5 h-2 w-2 rounded-full"
                  style={{ background: "#1DD223", boxShadow: "0 0 5px #1DD223" }}
                />
              )}
            </button>

            {notifOpen && (
              <div
                className="absolute right-0 z-50 mt-2 w-72 overflow-hidden rounded-[14px]"
                style={{
                  background: theme === "light" ? "rgba(255,255,255,0.98)" : "var(--atl-panel-strong)",
                  border: theme === "light" ? "1px solid rgba(15,23,42,0.12)" : "1px solid rgba(255,255,255,0.1)",
                  boxShadow: "0 12px 40px rgba(0,0,0,0.7)",
                  top: "calc(100% + 8px)",
                }}
              >
                <div className="px-4 py-3" style={{ borderBottom: "1px solid rgba(255,255,255,0.07)" }}>
                  <p className="text-sm font-semibold text-[var(--atl-text)]">Notifications</p>
                  <p className={`mt-0.5 text-xs ${theme === "light" ? "text-slate-600" : "text-white/40"}`}>
                    {notifEnabled
                      ? "Scan results will trigger a browser notification"
                      : "Notifications are muted"}
                  </p>
                </div>

                <div className="flex items-center justify-between gap-3 px-4 py-3">
                  <div>
                    <p className="text-sm font-medium text-[var(--atl-text)]">Scan alerts</p>
                    <p className={`mt-0.5 text-xs ${theme === "light" ? "text-slate-500" : "text-white/35"}`}>
                      Threat results &amp; warnings
                    </p>
                  </div>
                  <button
                    onClick={() => setNotifEnabled((v) => !v)}
                    className="relative h-6 w-12 flex-shrink-0 rounded-full transition-all duration-300 focus:outline-none focus:ring-2 focus:ring-[#4285F4]/50"
                    style={{
                      background: notifEnabled ? "#4285F4" : "#3a3a3a",
                      boxShadow: notifEnabled ? "0 0 10px rgba(66,133,244,0.45)" : "none",
                    }}
                    role="switch"
                    aria-checked={notifEnabled}
                    aria-label="Toggle notifications"
                  >
                    <span
                      className="absolute top-0.5 h-5 w-5 rounded-full bg-white shadow-md transition-all duration-300"
                      style={{ left: notifEnabled ? "calc(100% - 22px)" : "2px" }}
                    />
                  </button>
                </div>

                <div
                  className={`px-4 pb-3 text-[10px] leading-relaxed ${
                    theme === "light" ? "text-slate-500" : "text-white/25"
                  }`}
                  style={{ borderTop: "1px solid rgba(255,255,255,0.04)", paddingTop: "10px" }}
                >
                  Browser permission required. Clicking a notification opens the scan result.
                </div>

                <div
                  className="flex items-center gap-2 px-4 py-2.5"
                  style={{
                    background: notifEnabled
                      ? "rgba(29,210,35,0.07)"
                      : "rgba(239,68,68,0.07)",
                    borderTop: "1px solid rgba(255,255,255,0.05)",
                  }}
                >
                  <span
                    className="h-2 w-2 flex-shrink-0 rounded-full"
                    style={{
                      background: notifEnabled ? "#1DD223" : "#ef4444",
                      boxShadow: `0 0 5px ${notifEnabled ? "#1DD223" : "#ef4444"}`,
                    }}
                  />
                  <p className="text-xs font-semibold" style={{ color: notifEnabled ? "#1DD223" : "#ef4444" }}>
                    {notifEnabled ? "Notifications ON" : "Notifications OFF"}
                  </p>
                </div>
              </div>
            )}
          </div>

          <div className="relative" ref={profileMenuRef}>
            <button
              className="transition-opacity hover:opacity-80"
              aria-label="Profile"
              aria-expanded={profileMenuOpen}
              onClick={() => {
                setProfileMenuOpen((v) => !v);
                setProfileOpen(false);
              }}
            >
              <div
                className="flex h-9 w-9 items-center justify-center overflow-hidden rounded-full md:h-10 md:w-10"
                style={{
                  background: "var(--atl-surface-strong)",
                  border: "2.5px solid var(--atl-border)",
                  boxShadow: "0 0 0 2px rgba(54,130,218,0.25)",
                }}
              >
                {avatarPreview ? (
                  <img src={avatarPreview} alt="Profile" className="h-full w-full object-cover" />
                ) : initials ? (
                  <span className="select-none text-xs font-bold text-white">{initials}</span>
                ) : (
                  <svg viewBox="0 0 46 46" fill="none" xmlns="http://www.w3.org/2000/svg" className="h-full w-full">
                    <circle cx="22.5" cy="22.5" r="22.5" fill="#3a3a3a" />
                    <circle cx="22.5" cy="18.5" r="8.5" fill="#7a9cc4" />
                    <path
                      d="M35.5 41C35.5 37.0218 34.5777 36.2064 32.0459 33.3934C29.5142 30.5804 26.0804 29 22.5 29C18.9196 29 15.4858 30.5804 12.954 33.3934C10.4223 36.2064 10.5 37.0218 10.5 41L16.5 44L22.5 45L29.5 44L35.5 41Z"
                      fill="#7a9cc4"
                    />
                  </svg>
                )}
              </div>
            </button>

            {profileMenuOpen && (
              <div
                className="absolute right-0 z-50 mt-3 w-80 overflow-hidden rounded-[18px]"
                style={{
                  background: theme === "light" ? "rgba(255,255,255,0.98)" : "var(--atl-panel-strong)",
                  border: theme === "light" ? "1px solid rgba(15,23,42,0.12)" : "1px solid rgba(255,255,255,0.1)",
                  boxShadow: "0 20px 50px rgba(0,0,0,0.55)",
                  top: "calc(100% + 8px)",
                }}
              >
                <div
                  className="px-4 py-4"
                  style={{ background: theme === "light" ? "rgba(15,23,42,0.02)" : "rgba(255,255,255,0.03)" }}
                >
                  <div className="flex items-center gap-3">
                    <div
                      className="flex h-12 w-12 items-center justify-center overflow-hidden rounded-full"
                      style={{
                        background: "var(--atl-surface-strong)",
                        border: theme === "light" ? "1px solid rgba(15,23,42,0.12)" : "1px solid rgba(255,255,255,0.1)",
                      }}
                    >
                      {avatarPreview ? (
                        <img src={avatarPreview} alt="Profile" className="h-full w-full object-cover" />
                      ) : initials ? (
                        <span className="select-none text-sm font-bold text-white">{initials}</span>
                      ) : null}
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-semibold text-[var(--atl-text)]">
                        {savedProfile?.name || "Your Profile"}
                      </p>
                      <p className={`truncate text-xs ${theme === "light" ? "text-slate-600" : "text-white/45"}`}>
                        {savedProfile?.email || "Sign in to manage your profile"}
                      </p>
                    </div>
                  </div>
                </div>

                <div className="space-y-2 px-3 py-3">
                  <button
                    onClick={() => {
                      setProfileMenuOpen(false);
                      setProfileOpen(true);
                    }}
                    className="flex w-full items-center gap-3 rounded-xl px-3 py-3 text-left text-sm font-semibold text-[var(--atl-text)] transition hover:bg-white/8"
                  >
                    <span className="flex h-9 w-9 items-center justify-center rounded-full bg-[#4285f4]/15 text-[#77a9ff]">
                      <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M12 12a4 4 0 1 0-4-4 4 4 0 0 0 4 4Z" />
                        <path d="M4 20a8 8 0 0 1 16 0" />
                      </svg>
                    </span>
                    Open profile
                  </button>

                  <button
                    onClick={handleSignOut}
                    className="flex w-full items-center gap-3 rounded-xl px-3 py-3 text-left text-sm font-semibold text-[#ff8d8d] transition hover:bg-red-500/10"
                  >
                    <span className="flex h-9 w-9 items-center justify-center rounded-full bg-red-500/10 text-[#ff8d8d]">
                      <LogOut className="h-4 w-4" />
                    </span>
                    Sign out
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </nav>

      <div className="h-[5px] w-full" style={{ background: "var(--atl-border)" }} />
    </header>
  );
}

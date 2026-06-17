import { useEffect, useRef, useState } from "react";
import {
  Globe, FileSearch, Terminal, CheckCircle,
  Camera, Shield, AlertTriangle, AlertOctagon,
  Skull, ExternalLink, Loader2,
} from "lucide-react";
import Navbar from "@/components/Navbar";
import { NOTIF_KEY } from "@/components/Navbar";
import Footer from "@/components/Footer";
import ATLLogo from "@/components/ATLLogo";
import { Navigate } from "react-router-dom";
import { useTheme } from "@/hooks/use-theme";
import type { ScanResponse, ThreatLevel, RiskLevel, CompositeScore } from "../../shared/api";

type ScanTab = "url" | "file";

export type Profile = {
  name: string; mobile: string; username: string; email: string; avatarDataUrl?: string;
};
type ProfileErrors = Partial<Record<keyof Omit<Profile, "avatarDataUrl">, string>>;

const PROFILE_STORAGE_KEY = "atl-profile";
const AUTH_KEY = "atl-authenticated";
const EMPTY_PROFILE: Profile = { name: "", mobile: "", username: "", email: "", avatarDataUrl: "" };

// ── Step definitions for live terminal display ────────────────
type StepStatus = "waiting" | "running" | "done" | "error";
interface StepState {
  id:      string;
  label:   string;
  detail:  string;
  status:  StepStatus;
}

const INITIAL_URL_STEPS: StepState[] = [
  { id: "validate",  label: "URL Validation",         detail: "Waiting...", status: "waiting" },
  { id: "ml_features",label: "ML Feature Extraction", detail: "Waiting...", status: "waiting" },
  { id: "virustotal",label: "VirusTotal (70+ engines)",detail: "Waiting...", status: "waiting" },
  { id: "gsb",       label: "Google Safe Browsing",   detail: "Waiting...", status: "waiting" },
  { id: "abuseipdb", label: "AbuseIPDB",               detail: "Waiting...", status: "waiting" },
  { id: "ipqs",      label: "IPQualityScore",          detail: "Waiting...", status: "waiting" },
  { id: "urlscan",   label: "URLScan.io",              detail: "Waiting...", status: "waiting" },
  { id: "classify",  label: "Threat Classification",  detail: "Waiting...", status: "waiting" },
];

const INITIAL_FILE_STEPS: StepState[] = [
  { id: "upload",    label: "File Upload",             detail: "Waiting...", status: "waiting" },
  { id: "sha256",    label: "SHA256 Fingerprint",      detail: "Waiting...", status: "waiting" },
  { id: "virustotal",label: "VirusTotal (70+ engines)",detail: "Waiting...", status: "waiting" },
  { id: "classify",  label: "Threat Classification",  detail: "Waiting...", status: "waiting" },
];

function validateProfile(p: Profile): ProfileErrors {
  const errors: ProfileErrors = {};
  if (!p.name.trim()) errors.name = "Name is required.";
  if (!p.mobile.trim()) { errors.mobile = "Mobile number is required."; }
  else if (!/^\+?[\d\s\-()]{7,15}$/.test(p.mobile.trim())) errors.mobile = "Enter a valid mobile number.";
  if (!p.username.trim()) { errors.username = "Username is required."; }
  else if (!/^[a-zA-Z0-9_]{3,20}$/.test(p.username.trim())) errors.username = "3-20 chars, letters/digits/underscores only.";
  if (!p.email.trim()) { errors.email = "Email is required."; }
  else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(p.email.trim())) errors.email = "Enter a valid email address.";
  return errors;
}

function DefaultAvatar({ size = 64 }: { size?: number }) {
  return (
    <svg viewBox="0 0 46 46" fill="none" xmlns="http://www.w3.org/2000/svg" style={{ width: size, height: size }}>
      <circle cx="22.5" cy="22.5" r="22.5" fill="#e9eef9" />
      <circle cx="22.5" cy="18.5" r="8.5" fill="#9caac6" />
      <path d="M35.5 41C35.5 37.0218 34.5777 36.2064 32.0459 33.3934C29.5142 30.5804 26.0804 29 22.5 29C18.9196 29 15.4858 30.5804 12.954 33.3934C10.4223 36.2064 10.5 37.0218 10.5 41L16.5 44L22.5 45L29.5 44L35.5 41Z" fill="#9caac6" />
    </svg>
  );
}

// ── Threat config ─────────────────────────────────────────────
const THREAT_CONFIG: Record<ThreatLevel, {
  bg: string; border: string; icon: typeof Shield; iconColor: string; label: string; glow: string;
}> = {
  SAFE:     { bg: "#0d2a1a", border: "#1DD223", icon: Shield,       iconColor: "#1DD223", label: "Safe",     glow: "rgba(29,210,35,0.25)"  },
  WARNING:  { bg: "#2a2200", border: "#f59e0b", icon: AlertTriangle, iconColor: "#f59e0b", label: "Warning",  glow: "rgba(245,158,11,0.25)" },
  DANGER:   { bg: "#2a0a0a", border: "#ef4444", icon: AlertOctagon,  iconColor: "#ef4444", label: "Danger",   glow: "rgba(239,68,68,0.25)"  },
  CRITICAL: { bg: "#1a0a2a", border: "#a855f7", icon: Skull,         iconColor: "#a855f7", label: "Critical", glow: "rgba(168,85,247,0.35)" },
};

const RISK_BAR_COLOR: Record<RiskLevel, string> = {
  safe: "#1DD223", medium: "#f59e0b", high: "#ef4444", critical: "#a855f7",
};

// ── Threat category descriptions ──────────────────────────────
const THREAT_DESCRIPTIONS: Record<string, string> = {
  // Virus / Malware
  "Virus":                  "A virus is malicious code that attaches itself to legitimate files and spreads when executed. It can corrupt or delete files, steal sensitive data, hijack system resources, and silently install additional malware. Opening or downloading this resource may infect your device and any connected network.",
  "Trojan":                 "A Trojan disguises itself as legitimate software to trick users into installing it. Once active, it can open backdoors for remote attackers, steal passwords and banking credentials, log keystrokes, and give full control of your device to a threat actor without your knowledge.",
  "Malware":                "Malware is malicious software designed to damage, disrupt, or gain unauthorised access to your system. It encompasses viruses, worms, spyware, and more. It can exfiltrate personal data, encrypt your files for ransom, enroll your device in botnets, and cause irreversible system damage.",
  "Ransomware":             "Ransomware encrypts all files on the infected device and demands a ransom — typically in cryptocurrency — in exchange for the decryption key. Even after payment, restoration is not guaranteed. It can spread laterally across entire networks, locking organisations out of critical systems.",
  "Spyware":                "Spyware silently monitors your activity without consent. It records keystrokes, captures screenshots, tracks browsing history, and harvests credentials, credit card numbers, and personal communications. Data is secretly transmitted to remote attackers who exploit it for identity theft or financial fraud.",
  "Adware":                 "Adware injects unwanted advertisements into your browser and applications, often redirecting searches to malicious sites. Beyond being disruptive, it can track your online behaviour, degrade system performance, and act as a delivery mechanism for more severe malware payloads.",
  "Worm":                   "A worm is self-replicating malware that spreads automatically across networks without user interaction. It exploits security vulnerabilities to infect multiple machines, consume bandwidth, drop additional payloads, and create widespread disruption across entire organisations or the internet.",
  "Rootkit":                "A rootkit embeds itself deep in the operating system to hide malicious activity from security tools and the user. It grants persistent, privileged access to attackers, allowing them to install malware, intercept communications, and maintain long-term undetected control over the compromised device.",
  "Keylogger":              "A keylogger records every keystroke typed on the infected device — capturing passwords, credit card numbers, private messages, and banking PINs in real time. The collected data is silently transmitted to the attacker, enabling identity theft and financial fraud.",
  "Botnet":                 "This resource is linked to a botnet — a network of compromised devices controlled remotely by cybercriminals. Your device could be conscripted to launch DDoS attacks, distribute spam, mine cryptocurrency, or conduct large-scale fraud campaigns, all without your knowledge.",

  // Phishing
  "Phishing":               "This is a phishing page designed to impersonate a trusted website — such as a bank, email provider, or social network — in order to steal your login credentials, personal information, or financial details. Entering any information here will send it directly to attackers.",
  "Spear Phishing":         "This is a highly targeted phishing attack crafted for a specific individual or organisation. Using personalised details to appear legitimate, it attempts to steal sensitive credentials or financial information. These attacks are significantly more convincing than generic phishing attempts.",
  "Credential Harvesting":  "This page is engineered to harvest login credentials by mimicking a legitimate sign-in form. Any username, password, or authentication token submitted here is captured by attackers and used for account takeovers, identity theft, or sold on dark web marketplaces.",
  "Business Email Compromise": "This resource is associated with Business Email Compromise (BEC) — a sophisticated scam targeting organisations by impersonating executives or vendors to authorise fraudulent wire transfers or extract confidential data. BEC attacks cause billions in financial losses annually.",

  // Spam / Scam
  "Spam":                   "This URL is flagged as spam — typically used to promote fraudulent products, services, or schemes. Spam links often redirect to scam pages, drive-by download sites, or aggressive ad networks that can install unwanted software or expose your device to malicious content.",
  "Scam":                   "This is a scam website designed to defraud visitors through fake offers, false prizes, or deceptive investment schemes. Engaging with this site risks financial loss, identity theft, and exposure of personal information to fraudsters operating outside the reach of law enforcement.",
  "Fraud":                  "This resource is associated with online fraud — deliberate deception for financial or personal gain. It may involve fake shops, counterfeit goods, advance-fee schemes, or impersonation of legitimate services. Any transaction or personal disclosure here puts you at serious risk.",

  // Exploit / Hack
  "Exploit":                "This URL hosts or delivers exploit code that targets vulnerabilities in browsers, plugins, or operating systems. Simply visiting this page may trigger a drive-by download attack, silently installing malware on your device without any user interaction required.",
  "Drive-by Download":      "Visiting this page can silently download and execute malicious software on your device without any clicks required. It exploits unpatched vulnerabilities in your browser or its plugins, installing malware the moment the page loads.",
  "Command & Control":      "This domain is a Command & Control (C2) server used by malware to receive instructions from attackers and exfiltrate stolen data. If your device is communicating with this server, it has likely already been compromised and is part of a botnet.",
  "Malicious Redirect":     "This URL silently redirects visitors through a chain of malicious sites designed to exploit browser vulnerabilities, deliver malware, or land on phishing pages. The destination may look harmless but the redirect chain itself poses significant danger.",

  // Suspicious
  "Suspicious":             "This resource exhibits multiple indicators associated with malicious activity — including suspicious domain registration patterns, unusual network behaviour, and flagging by threat intelligence engines — but could not be definitively classified. Exercise extreme caution and avoid interacting with this content.",
  "Typosquatting":          "This domain is designed to impersonate a well-known brand by mimicking its name with a subtle spelling variation. It aims to deceive users who mistype URLs, redirecting them to phishing pages, malware distribution sites, or ad fraud networks.",
  "Newly Registered Domain":"This domain was registered very recently, a strong indicator of malicious intent. Cybercriminals routinely register fresh domains to evade reputation-based blocklists. Newly registered domains are disproportionately associated with phishing, malware distribution, and spam campaigns.",

  // Safe
  "Safe":                   "No threats were detected by any of the scanning engines. This resource appears to be legitimate and safe to access. Threat intelligence databases, ML analysis, and real-time API checks returned no indicators of compromise. Continue with normal caution.",
  "Legitimate":             "This resource has been assessed as legitimate. All scanning engines returned clean results with no evidence of malicious activity, phishing, malware, or suspicious behaviour. It is considered safe to access.",
};

function getThreatDescription(category: string, threat_label: string): string {
  if (THREAT_DESCRIPTIONS[category]) return THREAT_DESCRIPTIONS[category];
  // Fallback: match by keyword in category
  for (const key of Object.keys(THREAT_DESCRIPTIONS)) {
    if (category.toLowerCase().includes(key.toLowerCase())) return THREAT_DESCRIPTIONS[key];
  }
  // Final fallback by threat level
  if (threat_label === "SAFE")     return THREAT_DESCRIPTIONS["Safe"];
  if (threat_label === "WARNING")  return "This resource has raised warnings across one or more threat intelligence engines. While not confirmed malicious, it exhibits suspicious characteristics. Avoid submitting personal data or downloading any files from this source.";
  if (threat_label === "DANGER")   return "This resource has been flagged as dangerous by multiple threat intelligence systems. It poses a significant risk of malware infection, credential theft, or financial fraud. Do not interact with this content under any circumstances.";
  if (threat_label === "CRITICAL") return "This resource has been identified as a critical threat. It is actively being used in cyberattacks and poses an immediate risk to your device, data, and accounts. Disconnect from this resource immediately and run a full security scan on your device.";
  return "This resource has been flagged by ATL threat analysis. Exercise extreme caution and avoid interacting with this content.";
}

function scoreColor(v: number): string {
  if (v >= 75) return "#a855f7";
  if (v >= 50) return "#ef4444";
  if (v >= 25) return "#f59e0b";
  return "#1DD223";
}

// ── Live step terminal ─────────────────────────────────────────
function LiveTerminal({
  steps, scanning, target,
}: { steps: StepState[]; scanning: boolean; target: string }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    ref.current?.scrollTo({ top: ref.current.scrollHeight, behavior: "smooth" });
  }, [steps]);

  const icon = (s: StepStatus) => {
    if (s === "done")    return <span style={{ color: "#1DD223" }}>✓</span>;
    if (s === "error")   return <span style={{ color: "#ef4444" }}>✗</span>;
    if (s === "running") return <Loader2 className="w-3 h-3 animate-spin inline" style={{ color: "#4285F4" }} />;
    return <span style={{ color: "#555" }}>○</span>;
  };

  return (
    <div
      ref={ref}
      className="mt-4 rounded-[13px] p-4 font-mono text-xs h-[200px] overflow-y-auto"
      style={{ background: "rgba(0,0,0,0.80)", border: "1px solid rgba(54,130,218,0.35)" }}
    >
      <p className="text-white/30 mb-2 text-[10px] tracking-widest uppercase">
        ATL Terminal v2.0 — {target ? `Scanning: ${target}` : "Ready"}
      </p>
      {steps.map(step => (
        <div
          key={step.id}
          className="flex items-start gap-2 py-1 border-b border-white/[0.04] last:border-0"
        >
          {/* Status icon */}
          <span className="mt-0.5 w-4 flex-shrink-0 text-center text-sm">{icon(step.status)}</span>

          {/* Step info */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span
                className="font-semibold text-[11px]"
                style={{
                  color: step.status === "done"    ? "#1DD223"
                       : step.status === "running" ? "#4285F4"
                       : step.status === "error"   ? "#ef4444"
                       : "#555",
                }}
              >
                {step.label}
              </span>
              {step.status === "running" && (
                <span
                  className="text-[9px] px-1.5 py-0.5 rounded-full font-bold uppercase tracking-wider"
                  style={{ background: "rgba(66,133,244,0.2)", color: "#4285F4" }}
                >
                  processing
                </span>
              )}
            </div>
            {step.detail !== "Waiting..." && (
              <p className="text-white/40 text-[10px] mt-0.5 break-words leading-relaxed">
                {step.detail}
              </p>
            )}
          </div>
        </div>
      ))}
      {scanning && (
        <p className="text-white/20 text-[10px] mt-2 animate-pulse">
          ● Analysis in progress — do not close this tab
        </p>
      )}
    </div>
  );
}

// ── Composite Score Gauge ─────────────────────────────────────
function CompositeGauge({ composite }: { composite: CompositeScore }) {
  const overall   = composite.overall;
  const barColor  = scoreColor(overall);
  const breakdown = composite.breakdown;

  const sources: { label: string; key: keyof typeof breakdown; weight: string }[] = [
    { label: "ML Model",       key: "ml",        weight: "30%" },
    { label: "VirusTotal",     key: "vt",        weight: "35%" },
    { label: "AbuseIPDB",      key: "abuseipdb", weight: "15%" },
    { label: "IPQualityScore", key: "ipqs",      weight: "15%" },
    { label: "Google SB",      key: "gsb",       weight: "5%"  },
  ];

  return (
    <div className="rounded-[16px] p-4 mb-4"
      style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.07)" }}>
      <div className="flex items-center justify-between mb-2">
        <span className="text-white/60 text-xs uppercase tracking-widest font-semibold">
          Composite Danger Score
        </span>
        <span className="text-2xl font-black tabular-nums" style={{ color: barColor }}>
          {overall.toFixed(1)}<span className="text-sm font-normal text-white/30">/100</span>
        </span>
      </div>
      <div className="h-3 rounded-full mb-4 overflow-hidden" style={{ background: "rgba(255,255,255,0.08)" }}>
        <div className="h-full rounded-full transition-all duration-700"
          style={{ width: `${overall}%`, background: `linear-gradient(90deg,${barColor}99,${barColor})`, boxShadow: `0 0 10px ${barColor}` }} />
      </div>
      <div className="space-y-2">
        {sources.map(({ label, key, weight }) => {
          const val = breakdown[key];
          if (val === null || val === undefined) return null;
          const c = scoreColor(val);
          return (
            <div key={key}>
              <div className="flex items-center justify-between text-[11px] mb-1">
                <span className="text-white/50 flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                    style={{ background: c, boxShadow: `0 0 3px ${c}` }} />
                  {label}<span className="text-white/20"> ·{weight}</span>
                </span>
                <span className="font-semibold tabular-nums" style={{ color: c }}>{val.toFixed(1)}</span>
              </div>
              <div className="h-1.5 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.06)" }}>
                <div className="h-full rounded-full transition-all duration-500"
                  style={{ width: `${val}%`, background: c }} />
              </div>
            </div>
          );
        })}
      </div>
      <div className="mt-3 flex items-center gap-3 flex-wrap">
        {[
          { label: "Safe",     color: "#1DD223", range: "0–24"   },
          { label: "Warning",  color: "#f59e0b", range: "25–49"  },
          { label: "Danger",   color: "#ef4444", range: "50–74"  },
          { label: "Critical", color: "#a855f7", range: "75–100" },
        ].map(({ label, color, range }) => (
          <span key={label} className="flex items-center gap-1 text-[10px] text-white/30">
            <span className="w-2 h-2 rounded-full" style={{ background: color }} />
            {label}<span className="text-white/20"> ({range})</span>
          </span>
        ))}
      </div>
    </div>
  );
}

// ── Threat Result Panel ───────────────────────────────────────
function ThreatResultPanel({ result, target }: { result: ScanResponse; target: string }) {
  const cfg       = THREAT_CONFIG[result.threat_label];
  const ThreatIcon = cfg.icon;

  const engines = [
    { name: "ML Model",          value: result.ml ? `${result.ml.risk}% risk` : "—",                              ok: (result.ml?.risk ?? 0) < 50,                    show: !!result.ml },
    { name: "VirusTotal",        value: result.virustotal.success ? `${result.virustotal.malicious} malicious / ${result.virustotal.total} engines` : "Unavailable", ok: result.virustotal.malicious === 0, show: true },
    { name: "Google SafeBrowse", value: result.google_safebrowsing?.flagged ? result.google_safebrowsing.threat : "Clean",                                            ok: !result.google_safebrowsing?.flagged,    show: !!result.google_safebrowsing },
    { name: "AbuseIPDB",         value: result.abuseipdb?.success ? `Score ${result.abuseipdb.score}/100 (${result.abuseipdb.ip})` : "Unavailable",                  ok: (result.abuseipdb?.score ?? 0) < 25,     show: !!result.abuseipdb },
    { name: "IPQualityScore",    value: result.ipqualityscore?.success ? `Risk ${result.ipqualityscore.risk_score}/100` : "Unavailable",                              ok: (result.ipqualityscore?.risk_score ?? 0) < 50, show: !!result.ipqualityscore },
    { name: "URLScan.io",        value: result.urlscan?.success ? "Scan submitted" : "Unavailable",                                                                   ok: true,                                    show: !!result.urlscan && result.mode === "url" },
    { name: "Spam Detection",    value: result.ml?.is_spam ? `Detected (${result.ml.spam_conf}% confidence)` : "Clean",                                              ok: !result.ml?.is_spam,                     show: !!result.ml && result.mode === "url" },
  ].filter(e => e.show);

  return (
    <div className="w-full rounded-[22px] p-5 mt-4"
      style={{ background: cfg.bg, border: `1.5px solid ${cfg.border}`, boxShadow: `0 0 30px ${cfg.glow}` }}>
      {/* Header */}
      <div className="flex items-center gap-3 mb-4">
        <div className="w-12 h-12 rounded-full flex items-center justify-center flex-shrink-0"
          style={{ background: `${cfg.border}22`, border: `2px solid ${cfg.border}` }}>
          <ThreatIcon className="w-6 h-6" style={{ color: cfg.iconColor }} />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="text-white font-bold text-lg">{cfg.label}</span>
            <span className="text-xs font-semibold px-2 py-0.5 rounded-full"
              style={{ background: `${cfg.border}33`, color: cfg.border }}>
              {result.category}
            </span>
          </div>
          <p className="text-white/50 text-xs mt-0.5 truncate max-w-[280px]">
            {result.mode === "url" ? `🔗 ${target}` : `📁 ${result.filename ?? target}`}
          </p>
        </div>
      </div>

      {/* Threat description */}
      <div className="mb-4 rounded-xl px-4 py-3"
        style={{ background: `${cfg.border}14`, borderLeft: `3px solid ${cfg.border}` }}>
        <p className="text-[11px] uppercase tracking-widest mb-1.5" style={{ color: cfg.border }}>
          Threat Description
        </p>
        <p className="text-white/70 text-xs leading-relaxed">
          {getThreatDescription(result.category, result.threat_label)}
        </p>
      </div>

      {/* Composite gauge */}
      {result.composite && <CompositeGauge composite={result.composite} />}

      {/* VT breakdown — file mode */}
      {result.mode === "file" && result.virustotal.success && (
        <div className="mb-4 grid grid-cols-4 gap-2">
          {[
            { label: "Malicious",  val: result.virustotal.malicious,  color: "#ef4444" },
            { label: "Suspicious", val: result.virustotal.suspicious, color: "#f59e0b" },
            { label: "Harmless",   val: result.virustotal.harmless,   color: "#1DD223" },
            { label: "Undetected", val: result.virustotal.undetected, color: "#6b7280" },
          ].map(({ label, val, color }) => (
            <div key={label} className="rounded-xl p-2 text-center"
              style={{ background: "rgba(255,255,255,0.05)" }}>
              <div className="text-xl font-bold" style={{ color }}>{val}</div>
              <div className="text-[10px] text-white/40">{label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Engine list */}
      <div className="space-y-2">
        <p className="text-[10px] uppercase tracking-widest text-white/30 mb-2">Engine Results</p>
        {engines.map(({ name, value, ok }) => (
          <div key={name} className="flex items-center justify-between gap-2 text-xs">
            <span className="flex items-center gap-1.5 text-white/60 shrink-0">
              <span className="w-2 h-2 rounded-full flex-shrink-0"
                style={{ background: ok ? "#1DD223" : "#ef4444", boxShadow: `0 0 4px ${ok ? "#1DD223" : "#ef4444"}` }} />
              {name}
            </span>
            <span className="text-white/40 text-right truncate max-w-[180px]">{value}</span>
          </div>
        ))}
      </div>

      {result.urlscan?.success && result.urlscan.result && (
        <a href={result.urlscan.result} target="_blank" rel="noopener noreferrer"
          className="mt-3 flex items-center gap-1 text-xs text-[#3682DA] hover:underline">
          <ExternalLink className="w-3 h-3" />View URLScan report
        </a>
      )}

      {result.mode === "file" && result.virustotal.sha256 && result.virustotal.sha256 !== "N/A" && (
        <div className="mt-3 text-[10px] text-white/30 font-mono break-all">
          SHA256: {result.virustotal.sha256}
        </div>
      )}
    </div>
  );
}

// ── Browser notification helper ───────────────────────────────
async function fireScanNotification(result: ScanResponse, target: string): Promise<void> {
  if (!("Notification" in window)) return;

  // Request permission if not yet decided
  let perm = Notification.permission;
  if (perm === "default") {
    perm = await Notification.requestPermission();
  }
  if (perm !== "granted") return;

  const level = result.threat_label;
  const emoji =
    level === "CRITICAL" ? "☣️" :
    level === "DANGER"   ? "🔴" :
    level === "WARNING"  ? "🟡" : "🟢";

  const score = result.composite ? ` · Score ${result.composite.overall.toFixed(1)}/100` : "";
  const title = `${emoji} ATL: ${level} — ${result.category}`;
  const body  = `${result.mode === "url" ? "URL" : "File"}: ${target}${score}`;
  const pageUrl = window.location.href;

  const notif = new Notification(title, {
    body,
    icon:  "/favicon.ico",
    tag:   "atl-scan-result",  // replaces previous notification
    requireInteraction: level === "CRITICAL" || level === "DANGER",
  });

  // Clicking the notification focuses / reopens this tab
  notif.onclick = () => {
    window.focus();
    notif.close();
  };
}

// ── Main Page ─────────────────────────────────────────────────
export default function Index() {
  const theme = useTheme();
  const isLightTheme = theme === "light";
  const [isAuthenticated, setIsAuthenticated] = useState(() => window.localStorage.getItem(AUTH_KEY) !== null);
  const [activeTab,     setActiveTab]     = useState<ScanTab>("url");
  const [url,           setUrl]           = useState("");
  const [showTerminal,  setShowTerminal]  = useState(false);
  const [selectedFile,  setSelectedFile]  = useState<File | null>(null);
  const [profileOpen,   setProfileOpen]   = useState(false);
  const [scanning,      setScanning]      = useState(false);
  const [scanResult,    setScanResult]    = useState<ScanResponse | null>(null);
  const [scanTarget,    setScanTarget]    = useState("");
  const [scanError,     setScanError]     = useState<string | null>(null);
  const [steps,         setSteps]         = useState<StepState[]>(INITIAL_URL_STEPS);

  const [savedProfile,  setSavedProfile]  = useState<Profile>(EMPTY_PROFILE);
  const [draft,         setDraft]         = useState<Profile>(EMPTY_PROFILE);
  const [errors,        setErrors]        = useState<ProfileErrors>({});
  const [saveSuccess,   setSaveSuccess]   = useState(false);
  const [avatarPreview, setAvatarPreview] = useState<string>("");
  const successTimer   = useRef<ReturnType<typeof setTimeout> | null>(null);
  const avatarInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    try {
      const raw = window.localStorage.getItem(PROFILE_STORAGE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw) as Profile;
        setSavedProfile(parsed); setDraft(parsed);
        if (parsed.avatarDataUrl) setAvatarPreview(parsed.avatarDataUrl);
      }
    } catch { window.localStorage.removeItem(PROFILE_STORAGE_KEY); }
  }, []);

  useEffect(() => {
    if (profileOpen) {
      setDraft(savedProfile);
      setAvatarPreview(savedProfile.avatarDataUrl || "");
      setErrors({}); setSaveSuccess(false);
    }
  }, [profileOpen]); // eslint-disable-line

  // Update a specific step
  const updateStep = (id: string, patch: Partial<StepState>) => {
    setSteps(prev => prev.map(s => s.id === id ? { ...s, ...patch } : s));
  };

  // ── URL scan via SSE stream ──────────────────────────────────
  const handleUrlScan = async (target: string) => {
    const initSteps = INITIAL_URL_STEPS.map(s => ({ ...s }));
    setSteps(initSteps);
    setShowTerminal(true);

    // Mark validate as running immediately
    updateStep("validate", { status: "running", detail: "Sanitising and validating URL format..." });

    const resp = await fetch("/api/scan/url/stream", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url: target }),
    });

    if (!resp.ok || !resp.body) {
      throw new Error("Stream connection failed");
    }

    const reader  = resp.body.getReader();
    const decoder = new TextDecoder();
    let   buffer  = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop() ?? "";   // keep incomplete line

      for (const line of lines) {
        if (!line.startsWith("data: ")) continue;
        const raw = line.slice(6).trim();
        if (!raw) continue;

        let evt: Record<string, unknown>;
        try { evt = JSON.parse(raw); } catch { continue; }

        if (evt.type === "error") {
          throw new Error((evt.message as string) || "Analysis failed");
        }

        if (evt.type === "step") {
          const step   = evt.step   as string;
          const status = evt.status as StepStatus;
          const msg    = evt.message as string;
          updateStep(step, { status, detail: msg });
        }

        if (evt.type === "result") {
          // All steps done
          setSteps(prev => prev.map(s => ({ ...s, status: s.status === "running" ? "done" : s.status })));
          const result = evt as unknown as ScanResponse;
          setScanResult(result);

          // Fire browser notification if enabled
          const notifOn = (() => {
            try { return JSON.parse(localStorage.getItem(NOTIF_KEY) ?? "true") as boolean; }
            catch { return true; }
          })();
          if (notifOn) await fireScanNotification(result, target);
          return;
        }
      }
    }
  };

  // ── File scan (standard JSON — no SSE for files) ─────────────
  const handleFileScan = async (file: File) => {
    const initSteps = INITIAL_FILE_STEPS.map(s => ({ ...s }));
    setSteps(initSteps);
    setShowTerminal(true);

    updateStep("upload",    { status: "running", detail: `Uploading ${file.name} (${(file.size / 1024 / 1024).toFixed(1)} MB)...` });
    const fd = new FormData(); fd.append("file", file);
    updateStep("sha256",    { status: "running", detail: "Computing SHA256 fingerprint in 64 MB chunks..." });

    const resp = await fetch("/api/scan/file", { method: "POST", body: fd });
    updateStep("upload",    { status: "done", detail: `Uploaded ${file.name}` });
    updateStep("sha256",    { status: "running", detail: "Checking VirusTotal hash cache..." });
    updateStep("virustotal",{ status: "running", detail: "Querying VirusTotal — 70+ antivirus engines scanning..." });

    const data: ScanResponse = await resp.json();
    if (!resp.ok || data.error) throw new Error(data.error ?? "File scan failed");

    const vt = data.virustotal;
    updateStep("sha256",    { status: "done", detail: vt.sha256 ? `SHA256: ${vt.sha256.slice(0,16)}...` : "Hash computed" });
    updateStep("virustotal",{ status: "done", detail: vt.success ? `${vt.malicious} malicious, ${vt.suspicious} suspicious / ${vt.total} engines` : "Unavailable" });
    updateStep("classify",  { status: "running", detail: "Classifying threat category..." });

    await new Promise(r => setTimeout(r, 200)); // tiny pause for UX
    updateStep("classify",  { status: "done", detail: `${data.threat_label} — ${data.category}` });
    setScanResult(data);

    const notifOn = (() => {
      try { return JSON.parse(localStorage.getItem(NOTIF_KEY) ?? "true") as boolean; }
      catch { return true; }
    })();
    if (notifOn) await fireScanNotification(data, file.name);
  };

  // ── Main dispatcher ──────────────────────────────────────────
  const handleAnalyze = async () => {
    if (activeTab === "url"  && !url.trim())   return;
    if (activeTab === "file" && !selectedFile) return;

    setScanResult(null); setScanError(null); setScanning(true);
    const target = activeTab === "url" ? url.trim() : selectedFile!.name;
    setScanTarget(target);
    setSteps(activeTab === "url" ? INITIAL_URL_STEPS.map(s => ({ ...s })) : INITIAL_FILE_STEPS.map(s => ({ ...s })));

    try {
      if (activeTab === "url") await handleUrlScan(target);
      else                     await handleFileScan(selectedFile!);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setScanError(msg);
      setSteps(prev => prev.map(s =>
        s.status === "running" ? { ...s, status: "error", detail: msg } : s
      ));
    } finally {
      setScanning(false);
    }
  };

  const handleAvatarChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]; if (!file) return;
    const reader = new FileReader();
    reader.onload = ev => {
      const dataUrl = ev.target?.result as string;
      setAvatarPreview(dataUrl);
      setDraft(prev => ({ ...prev, avatarDataUrl: dataUrl }));
    };
    reader.readAsDataURL(file);
  };

  const handleSave = () => {
    const errs = validateProfile(draft);
    if (Object.keys(errs).length > 0) { setErrors(errs); return; }
    const trimmed: Profile = {
      name: draft.name.trim(), mobile: draft.mobile.trim(),
      username: draft.username.trim(), email: draft.email.trim(),
      avatarDataUrl: draft.avatarDataUrl || "",
    };
    setSavedProfile(trimmed); setDraft(trimmed);
    if (trimmed.avatarDataUrl) setAvatarPreview(trimmed.avatarDataUrl);
    window.localStorage.setItem(PROFILE_STORAGE_KEY, JSON.stringify(trimmed));
    setErrors({}); setSaveSuccess(true);
    if (successTimer.current) clearTimeout(successTimer.current);
    successTimer.current = setTimeout(() => setSaveSuccess(false), 3000);
  };

  const handleFieldChange = (key: keyof Omit<Profile, "avatarDataUrl">, value: string) => {
    setDraft(prev => ({ ...prev, [key]: value }));
    if (errors[key]) setErrors(prev => ({ ...prev, [key]: undefined }));
    setSaveSuccess(false);
  };

  const profileFields: { label: string; key: keyof Omit<Profile, "avatarDataUrl">; placeholder: string; type: string; autoComplete: string }[] = [
    { label: "Full Name",     key: "name",     placeholder: "Enter your full name", type: "text",  autoComplete: "name"     },
    { label: "Mobile No.",    key: "mobile",   placeholder: "+91 00000 00000",       type: "tel",   autoComplete: "tel"      },
    { label: "Username",      key: "username", placeholder: "e.g. john_doe",        type: "text",  autoComplete: "username" },
    { label: "Email Address", key: "email",    placeholder: "you@example.com",      type: "email", autoComplete: "email"    },
  ];

  const initials = savedProfile.name
    ? savedProfile.name.trim().split(" ").map(w => w[0]).join("").toUpperCase().slice(0, 2)
    : "";

  const getProfileInputStyle = (value: string, error?: string) => ({
    background: value.trim() ? "var(--atl-input-filled)" : "var(--atl-input-empty)",
    color: value.trim() ? "var(--atl-text)" : "var(--atl-input-text)",
    border: error ? "1.5px solid rgba(248,113,113,0.8)" : "1.5px solid rgba(255,255,255,0.1)",
  });

  const handleSignOut = () => {
    window.localStorage.removeItem(AUTH_KEY);
    setIsAuthenticated(false);
  };

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return (
    <div className="min-h-screen flex flex-col" style={{ background: "var(--atl-page-bg)" }}>
      <Navbar profileOpen={profileOpen} setProfileOpen={setProfileOpen}
              savedProfile={savedProfile} avatarPreview={avatarPreview} />

      <main className="flex-1 flex flex-col items-center px-4 py-10 md:py-16 lg:px-8">
        <div className="w-full max-w-[860px] flex flex-col items-center gap-8">
          <section className="w-full">
            <div className="w-full rounded-[30px] md:rounded-[46px] px-6 sm:px-10 md:px-14 py-8 md:py-12"
              style={{ background: "var(--atl-surface)", border: "1px solid rgba(255,255,255,0.06)",
                       backdropFilter: "blur(12px)", boxShadow: "0 8px 40px rgba(0,0,0,0.45)" }}>

              {/* Title */}
              <div className="flex items-center justify-center gap-3 mb-8">
                <ATLLogo className="w-10 h-9 md:w-14 md:h-12" withShield />
                <h1 className="text-[var(--atl-text)] font-bold text-3xl md:text-5xl leading-tight tracking-tight">
                  AI Threat Lens
                </h1>
              </div>

              {/* Tabs */}
              <div className="flex gap-3 mb-4">
                {(["url", "file"] as ScanTab[]).map(tab => (
                  <button key={tab}
                    onClick={() => { setActiveTab(tab); setScanResult(null); setScanError(null);
                                     setSteps(tab === "url" ? INITIAL_URL_STEPS.map(s=>({...s})) : INITIAL_FILE_STEPS.map(s=>({...s}))); }}
                    className="flex-1 flex items-center justify-center gap-2 h-[52px] md:h-[58px] rounded-[13px] font-medium text-base md:text-lg transition-all"
                    style={activeTab === tab
                      ? { background: "var(--atl-accent)", color: "#fff", boxShadow: "0 4px 18px rgba(66,133,244,0.45)" }
                      : { background: "rgba(255,255,255,0.06)", color: "var(--atl-text)", border: "2.5px solid var(--atl-border)" }}>
                    {tab === "url" ? <Globe className="w-5 h-5 flex-shrink-0" /> : <FileSearch className="w-5 h-5 flex-shrink-0" />}
                    <span>{tab === "url" ? "URL Scan" : "File / APK Scan"}</span>
                  </button>
                ))}
              </div>

              {/* Input */}
              {activeTab === "url" ? (
                <div className="mb-4">
                  <input type="url" placeholder="Enter Website URL" value={url}
                    onChange={e => { setUrl(e.target.value); setScanResult(null); setScanError(null); }}
                    onKeyDown={e => e.key === "Enter" && handleAnalyze()}
                    className="w-full h-[52px] md:h-[58px] rounded-[13px] px-5 text-base md:text-lg outline-none transition-all placeholder:text-[#404040]/50 focus:ring-2 focus:ring-[#3682DA]/40"
                    style={{ border: "2.5px solid var(--atl-border)", background: url.trim() ? "var(--atl-input-filled)" : "var(--atl-input-empty)", color: url.trim() ? "var(--atl-text)" : "var(--atl-input-text)" }} />
                </div>
              ) : (
                <div className="mb-4">
                  <label className="w-full h-[52px] md:h-[58px] rounded-[13px] flex items-center gap-3 cursor-pointer hover:opacity-90 transition-opacity"
                    style={{ border: "2.5px solid var(--atl-border)", background: selectedFile ? "var(--atl-input-filled)" : "var(--atl-input-empty)", padding: "0 20px" }}>
                    <input type="file" className="hidden"
                      onChange={e => { setSelectedFile(e.target.files?.[0] ?? null); setScanResult(null); setScanError(null); }}
                      accept=".apk,.exe,.pdf,.doc,.docx,.zip,.rar,.dmg,.js,.py,.sh,.bat" />
                    <FileSearch className="w-5 h-5 flex-shrink-0" style={{ color: selectedFile ? "var(--atl-text)" : "rgba(64,64,64,0.5)" }} />
                    <span className={`text-base md:text-lg font-normal truncate ${selectedFile ? "text-[var(--atl-text)]" : "text-[#404040]/50"}`}>
                      {selectedFile ? selectedFile.name : "Choose a file (.apk, .exe, .pdf, .zip…)"}
                    </span>
                  </label>
                </div>
              )}

              {/* Analyze Button */}
              <button onClick={handleAnalyze}
                disabled={scanning || (activeTab === "url" ? !url.trim() : !selectedFile)}
                className="w-full h-[52px] md:h-[58px] rounded-[13px] text-white font-semibold text-base md:text-lg transition-all mb-5 active:scale-[0.99] disabled:opacity-45 disabled:cursor-not-allowed hover:brightness-110"
                style={{ background: "var(--atl-accent)", boxShadow: "0 4px 16px rgba(66,133,244,0.3)" }}>
                {scanning ? (
                  <span className="flex items-center justify-center gap-2">
                    <Loader2 className="animate-spin h-5 w-5" />Analyzing...
                  </span>
                ) : (activeTab === "url" ? "Analyze URL" : "Analyze File")}
              </button>

              {/* Terminal toggle */}
              <div className="flex justify-center">
                <button onClick={() => setShowTerminal(v => !v)}
                  className="flex items-center gap-2 text-white/55 hover:text-[var(--atl-text)] text-sm font-medium transition-colors px-3 py-1.5 rounded-lg hover:bg-white/[0.06]">
                  <Terminal className="w-4 h-4" />
                  <span>Toggle Terminal</span>
                </button>
              </div>

              {/* Live terminal — shown during scan and after */}
              {showTerminal && (
                <LiveTerminal steps={steps} scanning={scanning} target={scanTarget} />
              )}

              {/* Error */}
              {scanError && (
                <div className="mt-4 rounded-[13px] p-4 text-sm"
                  style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.4)", color: "#fca5a5" }}>
                  ⚠️ {scanError.includes("ML engine") || scanError.includes("unreachable")
                    ? "Analysis engine is starting up. Please ensure the Python server is running and try again."
                    : scanError}
                </div>
              )}

              {/* Results */}
              {scanResult && <ThreatResultPanel result={scanResult} target={scanTarget} />}
            </div>

            <p
              className="mt-8 max-w-[680px] px-2 text-center text-base font-semibold leading-relaxed md:text-xl"
              style={{ color: isLightTheme ? "rgba(18,32,51,0.78)" : "rgba(255,255,255,0.70)" }}
            >
              Analyse suspicious files, domains and URLs to detect malware and other breaches,
              automatically share with the security community.
            </p>

            <div className="mt-8 flex items-stretch justify-center divide-x divide-white/15">
              {[{ n: "70+", l: "Antivirus Engines" }, { n: "2M+", l: "Scans Per Day" }, { n: "99.9%", l: "Detection Rate" }].map(({ n, l }) => (
                <div key={l} className="flex flex-col items-center gap-1 px-8 sm:px-14 py-2">
                  <span
                    className="text-2xl font-bold tracking-tight md:text-3xl"
                    style={{ color: isLightTheme ? "#183153" : "#ffffff" }}
                  >
                    {n}
                  </span>
                  <span
                    className="text-center text-xs sm:text-sm"
                    style={{ color: isLightTheme ? "rgba(24,49,83,0.62)" : "rgba(255,255,255,0.45)" }}
                  >
                    {l}
                  </span>
                </div>
              ))}
            </div>
          </section>
        </div>
      </main>

      {/* Profile Panel */}
      {profileOpen && (
        <div className="fixed inset-0 z-40 flex items-start justify-end" role="dialog" aria-modal="true">
          <div className="absolute inset-0" onClick={() => setProfileOpen(false)} />
          <div
            className="relative z-10 mr-4 mt-[86px] flex w-full max-w-[320px] flex-col overflow-hidden rounded-[24px] text-white shadow-[0_24px_80px_rgba(0,0,0,0.6)] sm:mr-6"
            style={{
              maxHeight: "calc(100vh - 110px)",
              border: "1px solid rgba(76,131,201,0.55)",
              background: "var(--atl-panel-strong)",
            }}
          >
            <div
              className="relative px-5 pb-4 pt-6 text-center"
              style={{
                background:
                  "linear-gradient(180deg, rgba(66,133,244,0.26) 0%, rgba(36,61,112,0.96) 100%)",
              }}
            >
              <div className="relative mx-auto mb-4 group w-fit">
                <button
                  onClick={() => avatarInputRef.current?.click()}
                  className="relative flex h-24 w-24 items-center justify-center overflow-hidden rounded-full border border-white/15 focus:outline-none"
                  style={{ background: "#e9eef9", boxShadow: "0 0 0 4px rgba(66,133,244,0.25)" }}
                >
                  {avatarPreview ? (
                    <img src={avatarPreview} alt="Profile" className="h-full w-full object-cover" />
                  ) : (
                    <div className="flex h-full w-full items-center justify-center bg-white text-[#9aa9c7]">
                      <svg viewBox="0 0 46 46" fill="none" xmlns="http://www.w3.org/2000/svg" className="h-14 w-14">
                        <circle cx="23" cy="18" r="8" fill="currentColor" />
                        <path d="M10 40c0-7.2 5.9-13 13-13s13 5.8 13 13" stroke="currentColor" strokeWidth="4" strokeLinecap="round" />
                      </svg>
                    </div>
                  )}
                  <div className="absolute inset-0 flex items-center justify-center rounded-full bg-black/40 opacity-0 transition-opacity group-hover:opacity-100">
                    <Camera className="h-5 w-5 text-white" />
                  </div>
                </button>
                <input
                  ref={avatarInputRef}
                  type="file"
                  accept="image/*"
                  className="hidden"
                  onChange={handleAvatarChange}
                />
                <button
                  onClick={() => avatarInputRef.current?.click()}
                  className="absolute bottom-0 right-0 flex h-7 w-7 items-center justify-center rounded-full"
                  style={{ background: "var(--atl-accent)", border: "2px solid #243d70" }}
                  aria-label="Change avatar"
                >
                  <Camera className="h-3.5 w-3.5 text-white" />
                </button>
              </div>

              <p className="text-2xl font-bold leading-tight text-white">
                {draft.name || savedProfile.name || "Your Profile"}
              </p>
              {(draft.username || savedProfile.username) && (
                <p className="mt-1 text-xs font-semibold tracking-wide" style={{ color: "#8ec0ff" }}>
                  @{draft.username || savedProfile.username}
                </p>
              )}
              <p className="mt-1 text-sm text-white/60">
                {savedProfile.email || "Complete your profile below"}
              </p>

            </div>

            <div className="flex-1 space-y-3 overflow-y-auto overscroll-contain px-4 py-4">
              {profileFields.map((field) => (
                <div key={field.key}>
                  <label className="block">
                    <span className="mb-1.5 block text-[10px] font-semibold uppercase tracking-[0.2em] text-white/50">
                      {field.label}
                    </span>
                    <input
                      type={field.type}
                      value={draft[field.key]}
                      autoComplete={field.autoComplete}
                      onChange={(e) => handleFieldChange(field.key, e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && handleSave()}
                      placeholder={field.placeholder}
                      className="h-11 w-full rounded-[12px] px-4 text-sm outline-none transition-all placeholder:text-white/35"
                      style={getProfileInputStyle(draft[field.key], errors[field.key])}
                    />
                  </label>
                  {errors[field.key] && (
                    <p className="mt-1 pl-1 text-xs leading-snug text-red-400">{errors[field.key]}</p>
                  )}
                </div>
              ))}
            </div>

            <div className="space-y-3 border-t border-white/10 px-5 pb-5 pt-3">
              {saveSuccess && (
                <div className="flex items-center gap-2 text-sm text-green-400">
                  <CheckCircle className="h-4 w-4 flex-shrink-0" />
                  <span>Profile saved successfully!</span>
                </div>
              )}

              <button
                onClick={handleSave}
                className="h-11 w-full rounded-[12px] text-sm font-semibold text-white transition-all active:scale-[0.98] hover:brightness-110"
                style={{ background: "var(--atl-accent)", boxShadow: "0 3px 12px rgba(66,133,244,0.35)" }}
              >
                Save Profile
              </button>
            </div>
          </div>
        </div>
      )}

      <Footer />
    </div>
  );
}

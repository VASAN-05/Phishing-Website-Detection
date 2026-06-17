import { useEffect, useState } from "react";

export type ThemeMode = "dark" | "light";

function readTheme(): ThemeMode {
  return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

export function applyTheme(nextTheme: ThemeMode) {
  document.documentElement.dataset.theme = nextTheme;
  window.localStorage.setItem("atl-theme", nextTheme);
  window.dispatchEvent(new CustomEvent("atl-theme-change", { detail: nextTheme }));
}

export function useTheme() {
  const [theme, setTheme] = useState<ThemeMode>(readTheme);

  useEffect(() => {
    const sync = () => setTheme(readTheme());
    window.addEventListener("atl-theme-change", sync as EventListener);
    window.addEventListener("storage", sync);
    return () => {
      window.removeEventListener("atl-theme-change", sync as EventListener);
      window.removeEventListener("storage", sync);
    };
  }, []);

  return theme;
}

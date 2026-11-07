import type { CSSProperties } from "react";

export function Icon({ name, size = 20 }: { name: "settings" | "edit" | "trash" | "plus" | "send" | "sync" | "lock" | "arrow" | "back" | "close" | "copy" | "check" | "mail"; size?: number }) {
  const paths = {
    settings: <><path d="M4 7h16M4 17h16" /><circle cx="9" cy="7" r="3" fill="var(--panel, #2a2331)" /><circle cx="15" cy="17" r="3" fill="var(--panel, #2a2331)" /></>,
    edit: <><path d="m15 4 5 5M4 20l5-1L21 7l-4-4L5 15l-1 5Z" /></>,
    trash: <><path d="M3 6h18M9 6V4h6v2M5 6l1 14h12l1-14M10 10v6m4-6v6" /></>,
    plus: <path d="M12 5v14M5 12h14" />,
    send: <><path d="m21 3-7 18-4-7-7-4 18-7Z" /><path d="m10 14 5-5" /></>,
    sync: <><path d="M20 8a8 8 0 0 0-13-3L3 8m0-5v5h5M4 16a8 8 0 0 0 13 3l4-3m0 5v-5h-5" /></>,
    lock: <><rect x="5" y="10" width="14" height="11" rx="3" /><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2" /></>,
    arrow: <path d="M5 12h14m-5-5 5 5-5 5" />,
    back: <path d="M19 12H5m5-5-5 5 5 5" />,
    close: <path d="m6 6 12 12M18 6 6 18" />,
    copy: <><rect x="8" y="8" width="12" height="12" rx="2" /><path d="M15 4H6a2 2 0 0 0-2 2v9" /></>,
    check: <path d="m5 12 4 4L19 6" />,
    mail: <><rect x="3" y="5" width="18" height="14" rx="3" /><path d="m3 6 9 7 9-7" /></>,
  };
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>;
}

export function CatMark({ className = "", style }: { className?: string; style?: CSSProperties }) {
  return <svg className={className} style={style} viewBox="0 0 48 48" fill="none" aria-hidden="true">
    <path d="M8 22 6 7l13 9c3-1 7-1 10 0L42 7l-2 15c3 5 3 12-2 17-8 8-20 8-28 0-5-5-5-12-2-17Z" fill="currentColor" />
    <path d="m14 28 4 1m12 0 4-1m-12 5 2 2 2-2m-2 2v3" stroke="#241c2b" strokeWidth="2.6" strokeLinecap="round" />
    <path d="m2 32 8 1m28 0 8-1M3 38l8-2m26 0 8 2" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
  </svg>;
}

export function CatIllustration() {
  return <svg className="cat-illustration" viewBox="0 0 420 290" fill="none" aria-hidden="true">
    <ellipse cx="210" cy="245" rx="142" ry="13" fill="#14101a" opacity=".35" />
    <circle cx="213" cy="135" r="106" fill="#322938" />
    <circle cx="213" cy="135" r="105.5" stroke="#534153" strokeDasharray="3 9" />
    <path d="M302 209c51 14 40-58 3-29" stroke="#f1c27c" strokeWidth="19" strokeLinecap="round" />
    <path d="M147 241c-3-49 6-92 56-101 39-6 76 20 78 64l3 37H147Z" fill="#e9b46e" />
    <path d="M181 175c-5 12-10 37-8 66h63c2-22-1-41-10-56" fill="#f7dec0" />
    <path d="m154 111-2-56 39 29c14-5 32-4 47 2l36-25-4 55c8 13 8 39-9 53-24 20-66 22-91 0-18-15-23-36-16-58Z" fill="#f1c27c" />
    <path d="m163 73 22 16-23 11-1-27Zm98 5-19 14 18 10 1-24Z" fill="#b37b70" />
    <path d="M183 128c3 4 9 4 12 0m33 0c3 4 9 4 12 0" stroke="#352736" strokeWidth="4" strokeLinecap="round" />
    <path d="m204 139 7 5 7-5h-14Z" fill="#8c5452" />
    <path d="M211 145v6m-7-1c3 5 10 5 14 0" stroke="#8c5452" strokeWidth="2.5" strokeLinecap="round" />
    <path d="m143 135 32 3m-36 10 33-3m76-7 30-3m-30 8 35 5" stroke="#f7dec0" strokeWidth="2" strokeLinecap="round" />
    <path d="M189 94h9m9-3h9m9 3h9" stroke="#cd925d" strokeWidth="6" strokeLinecap="round" />
    <rect x="107" y="212" width="182" height="36" rx="13" fill="#a492c2" />
    <rect x="107" y="212" width="182" height="13" rx="6.5" fill="#b6a4d2" />
    <path d="M178 204c-10-7-20-6-26 2-2 4 2 7 7 6h17c7 0 7-4 2-8Zm49 0c10-7 20-6 26 2 2 4-2 7-7 6h-17c-7 0-7-4-2-8Z" fill="#f1c27c" />
    <path d="M316 88h45a10 10 0 0 1 10 10v16a10 10 0 0 1-10 10h-24l-16 12v-12h-5a10 10 0 0 1-10-10V98a10 10 0 0 1 10-10Z" fill="#baa6d6" />
    <circle cx="323" cy="106" r="3" fill="#47364f" /><circle cx="338" cy="106" r="3" fill="#47364f" /><circle cx="353" cy="106" r="3" fill="#47364f" />
    <path d="m87 103 3-10 3 10 10 3-10 3-3 10-3-10-10-3 10-3Zm244 61 2-7 2 7 7 2-7 2-2 7-2-7-7-2 7-2Z" fill="#e8b87c" />
    <circle cx="98" cy="175" r="3" fill="#a492c2" /><circle cx="288" cy="63" r="3" fill="#a492c2" />
    <path d="M119 76c-5-5-11-5-16 0" stroke="#806a89" strokeWidth="2" strokeLinecap="round" />
  </svg>;
}

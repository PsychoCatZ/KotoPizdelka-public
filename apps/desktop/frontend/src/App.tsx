import { ProfileBackupForm, type BackupMode } from "./ProfileBackup";
import { profileBackup } from "./api";
import { AccountsPanel } from "./AccountsPanel";
import type { AccountView } from "./api";
import { useEffect, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { listen } from "@tauri-apps/api/event";
import { api, inNative } from "./api";
import type { ContactView, HistoryEntry, InvitationExport, BackgroundSettings, NotificationSettings, ProfileStatus, QuickInvitationExport, VerificationView } from "./api";
import { CatIllustration, CatMark, Icon } from "./Art";
import { ForegroundSyncScheduler, singleFlightSync, canSyncStage } from "./foregroundSync";
import { appendHistoryTail, mergeHistory } from "./historyTail";
import { QuickInvitationForm, QuickInvitationExport as QuickExportPanel } from "./QuickInvitation";
import { normalizeInvitationLink } from "./invitationLink";
import { hasVisibleMessage, VisibleReadBatcher } from "./visibleUnread";

type ModalState = { kind: "backup"; mode: BackupMode } | { kind: "settings" } | { kind: "account" } | { kind: "profile" } | { kind: "alias"; contact: string; alias: string; nickname: string } | { kind: "create" | "legacy_create" | "legacy_accept" } | { kind: "accept"; link?: string } | { kind: "complete" | "confirm"; contact: string } | { kind: "retry"; contact: string; quick?: boolean } | { kind: "delete"; contact: string; invitation: boolean } | { kind: "export"; data: InvitationExport } | { kind: "quick_export"; data: QuickInvitationExport } | { kind: "verify"; contact: string; data: VerificationView };
const shortId = (id: string) => id.slice(0, 8);
const contactName = (contact: ContactView) => contact.alias || contact.nickname || `Контакт ${shortId(contact.id)}`;
const MAX_TEXT_BYTES = 24 * 1024;
const desktopSync = inNative && !/Android/i.test(navigator.userAgent);
const canSyncHere = () => desktopSync || document.visibilityState === "visible";
const AUTO_SYNC_SETTING = "koto.auto-sync.v1";
function initialAutoSync() {
  try { return localStorage.getItem(AUTO_SYNC_SETTING) !== "false"; }
  catch { return true; }
}
const stageText = { archived: "Архив после восстановления", queue_pending: "Очередь ждёт создания", offer_pending: "Ждём ответ на приглашение", waiting_first_message: "Ждём первое сообщение", ready: "Можно мяукать", legacy: "Ранее созданный контакт", quick_queue_pending: "Готовим приглашение", quick_pending: "Ждём нового кота", quick_confirmation: "Подтвердите знакомство", quick_waiting: "Ждём подтверждение", quick_expired: "Приглашение истекло" };

function Alerts({ error, notice, clearError, clearNotice }: { error: string | null; notice: string | null; clearError: () => void; clearNotice: () => void }) {
  return <div className="alerts" aria-live="polite">{error && <div className="alert error" role="alert"><span>{error}</span><button className="icon-button" onClick={clearError} aria-label="Скрыть ошибку"><Icon name="close" size={16} /></button></div>}{notice && <div className="alert success"><Icon name="check" size={17} /><span>{notice}</span><button className="icon-button" onClick={clearNotice} aria-label="Скрыть уведомление"><Icon name="close" size={16} /></button></div>}</div>;
}

function SyncMode({ enabled, status, toggle }: { enabled: boolean; status: string; toggle: () => void }) {
  return <div className="sync-mode"><div className="sync-mode-heading"><button className="sync-mode-toggle" type="button" role="switch" aria-label="Автоматическая синхронизация" aria-checked={enabled} onClick={toggle}><span className="switch-track"><span /></span></button><span>Автосинхронизация</span></div><p role="status" aria-label="Состояние синхронизации">{status}</p></div>;
}

function Modal({ title, children, busy, onClose, quickInvitation = false }: { title: string; children: ReactNode; busy: boolean; onClose: () => void; quickInvitation?: boolean }) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => { dialog.current?.showModal(); }, []);
  return <dialog ref={dialog} className={`modal${quickInvitation ? " modal-quick-invitation" : ""}`} onCancel={event => { event.preventDefault(); if (!busy) onClose(); }} aria-label={title}>
    <div className="modal-header"><div><span className="eyebrow">СВОЯ СТАЯ. СВОИ ПРАВИЛА.</span><h2>{title}</h2></div><button className="icon-button" aria-label="Закрыть окно" disabled={busy} onClick={onClose}><Icon name="close" /></button></div>
    {children}
  </dialog>;
}

function InvitationForm({ kind, busy, submit }: { kind: "create" | "accept" | "complete"; busy: boolean; submit: (fields: { invitation: string; fingerprint: string; relay: string; ticket: string }) => void }) {
  const [invitation, setInvitation] = useState("");
  const [fingerprint, setFingerprint] = useState("");
  const [relay, setRelay] = useState("https://relay.example.invalid");
  const [ticket, setTicket] = useState("");
  function onSubmit(event: FormEvent) {
    event.preventDefault();
    submit({ invitation: invitation.trim(), fingerprint: fingerprint.trim().toLowerCase(), relay: relay.trim(), ticket: ticket.trim().toLowerCase() });
  }
  return <form className="modal-body" onSubmit={onSubmit} autoComplete="off">
    <p className="form-intro">{kind === "create" ? "Пригласите одного собеседника. Он пришлёт ответ — и у вашей стаи появится личный разговор." : kind === "accept" ? "Получили приглашение? Проверьте отпечаток и подготовьте свою очередь для ответов." : "Остался один шаг: проверьте отпечаток ответа. После этого вы сможете отправить первое сообщение."}</p>
    {kind !== "create" && <>
      <label>Текст {kind === "accept" ? "приглашения" : "ответа"}<textarea className="artifact-input" value={invitation} onChange={event => setInvitation(event.target.value)} rows={4} maxLength={8192} required disabled={busy} spellCheck={false} placeholder="Вставьте полученный текст целиком" /></label>
      <label>Отпечаток из доверенного канала<input className="mono" value={fingerprint} onChange={event => setFingerprint(event.target.value)} pattern="[a-fA-F0-9]{64}" maxLength={64} required disabled={busy} spellCheck={false} autoCapitalize="off" placeholder="64 шестнадцатеричных символа" /></label>
      <div className="form-note"><Icon name="lock" size={17} /><span>Получите отпечаток лично или по заранее доверенному каналу. Значение из присланного текста не подтверждает собеседника.</span></div>
    </>}
    {kind !== "complete" && <div className="relay-fields">
      <details><summary>Другой сервер (необязательно)</summary><label>Адрес сервера очередей<input type="url" value={relay} onChange={event => setRelay(event.target.value)} required disabled={busy} placeholder="https://адрес-вашего-сервера" spellCheck={false} autoCapitalize="off" /></label></details>
      <label>Билет на создание очереди<input type="password" value={ticket} onChange={event => setTicket(event.target.value)} pattern="[a-fA-F0-9]{64}" maxLength={64} required disabled={busy} autoComplete="off" autoCapitalize="off" spellCheck={false} placeholder="Одноразовый билет от владельца сервера" /></label>
      <p className="field-hint">Билет создаёт одну очередь. Сервер должен использовать HTTPS.</p>
    </div>}
    <button className="button primary full" type="submit" disabled={busy}>{busy ? "Минуточку, кот работает…" : kind === "create" ? "Создать приглашение" : kind === "accept" ? "Проверить и принять" : "Проверить и завершить"}<Icon name="arrow" size={18} /></button>
  </form>;
}

function NameForm({ value, peer, busy, submit }: { value: string; peer?: string; busy: boolean; submit: (value: string) => void }) {
  const [name, setName] = useState(value || "");
  const [error, setError] = useState<string | null>(null);
  const own = peer === undefined;
  return <form className="modal-body" onSubmit={event => {
    event.preventDefault(); const normalized = name.trim();
    if ([...normalized].length > 48 || /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069\u200b\u200e\u200f\ufeff]/u.test(normalized)) { setError("До 48 символов, без управляющих и невидимых символов."); return; }
    submit(normalized);
  }}>
    <p className="form-intro">{own ? "Придумай себе ник. Его увидят твои собеседники; он передаётся внутри шифрованного обмена." : "Как подписать этого кота у себя? Собеседнику это название не отправляется."}</p>
    {!own && <p className="field-hint">Ник собеседника: {peer || "ещё не передан"}</p>}
    <label>{own ? "Мой ник" : "Название у меня"}<input autoFocus value={name} onChange={event => { setName(event.target.value); setError(null); }} maxLength={96} disabled={busy} autoComplete="off" placeholder={own ? "Например, Кот Учёный" : peer || "Например, Друг Барсик"} /></label>
    {error && <p className="inline-error" role="alert">{error}</p>}
    <p className="field-hint">{own ? "Ники могут совпадать и не подтверждают личность. Пустое поле убирает ник." : "Пустое поле вернёт ник собеседника или номер контакта."}</p>
    <button className="button primary full" disabled={busy} type="submit">{busy ? "Сохраняем…" : "Сохранить"}<Icon name="check" size={17} /></button>
  </form>;
}

function ExportPanel({ data }: { data: InvitationExport }) {
  const [copied, setCopied] = useState<"invitation" | "fingerprint" | null>(null);
  const [copyError, setCopyError] = useState(false);
  async function copy(which: "invitation" | "fingerprint") {
    try { await navigator.clipboard.writeText(data[which]); setCopied(which); setCopyError(false); }
    catch { setCopyError(true); }
  }
  return <div className="modal-body">
    <p className="form-intro">Передайте текст собеседнику. Полный отпечаток сообщите отдельно — лично или по уже доверенному каналу.</p>
    <label>Текст для собеседника<textarea className="artifact-input export-text" value={data.invitation} readOnly rows={5} spellCheck={false} aria-label="Текст приглашения для экспорта" /></label>
    <button className="button secondary" onClick={() => void copy("invitation")}><Icon name={copied === "invitation" ? "check" : "copy"} size={16} />{copied === "invitation" ? "Текст скопирован" : "Скопировать текст"}</button>
    <label className="fingerprint-label">Полный отпечаток<textarea className="fingerprint-value" value={data.fingerprint} readOnly rows={2} spellCheck={false} aria-label="Полный отпечаток приглашения" /></label>
    <button className="button secondary" onClick={() => void copy("fingerprint")}><Icon name={copied === "fingerprint" ? "check" : "copy"} size={16} />{copied === "fingerprint" ? "Отпечаток скопирован" : "Скопировать отпечаток"}</button>
    <div className="form-note"><Icon name="mail" size={17} /><span>В тексте есть право отправки в вашу очередь. Передавайте его только выбранному собеседнику.</span></div>
    {copyError && <p className="inline-error" role="alert">Буфер обмена недоступен. Выделите текст и скопируйте вручную.</p>}
  </div>;
}

function RetryForm({ busy, quick, automatic = false, submit }: { busy: boolean; quick?: boolean; automatic?: boolean; submit: (ticket: string | null) => void }) {
  const [ticket, setTicket] = useState("");
  return <form className="modal-body" autoComplete="off" onSubmit={event => { event.preventDefault(); submit(ticket.trim().toLowerCase() || null); }}>
    <p className="form-intro">Создание очереди ещё не подтверждено сервером. Повторим сохранённую попытку, чтобы завершить приглашение.</p>
    {automatic ? <p className="field-hint">Продолжим сохранённую подготовку через твой аккаунт. Вводить билет не нужно.</p> : <>
    <label>Новый билет, если прежний не подходит или истёк<input type="password" value={ticket} onChange={event => setTicket(event.target.value)} pattern="[a-fA-F0-9]{64}" maxLength={64} disabled={busy} autoComplete="off" autoCapitalize="off" spellCheck={false} placeholder="Можно оставить пустым" /></label>
    <p className="field-hint">Пустое поле повторяет попытку с сохранённым билетом. Новый билет можно получить у владельца сервера.{quick && " Для ссылки и QR-кода нужен билет с правом приглашать: issue-ticket.sh --invite."}</p>
    </>}
    <button className="button primary full" type="submit" disabled={busy}>{busy ? "Договариваемся с очередью…" : "Повторить создание очереди"}<Icon name="sync" size={17} /></button>
  </form>;
}

function VerificationPanel({ data, busy, mark }: { data: VerificationView; busy: boolean; mark: () => void }) {
  const [compared, setCompared] = useState(false);
  const valid = /^[a-f0-9]{64}$/.test(data.fingerprint);
  return <div className="modal-body">
    <p className="form-intro">Откройте «Проверить собеседника» на обоих устройствах. Сравните весь код лично или по заранее доверенному каналу. Код должен совпасть целиком.</p>
    {valid ? <p className="verification-code" aria-label="Код проверки собеседника">{data.fingerprint.match(/.{1,8}/g)?.join(" ")}</p> : <p className="inline-error" role="alert">Код проверки недоступен. Закройте окно и попробуйте ещё раз.</p>}
    <div className="form-note"><Icon name="lock" size={17} /><span>Код, присланный в этом же разговоре или вместе с приглашением, не подтверждает личность независимо.</span></div>
    {data.verified ? <p className="verified-note"><Icon name="check" size={18} />Личность отмечена как проверенная на этом устройстве.</p> : <><label className="verification-checkbox"><input type="checkbox" checked={compared} onChange={event => setCompared(event.target.checked)} disabled={busy || !valid} /><span>Сверил весь код через независимый канал</span></label><button className="button primary full" disabled={busy || !valid || !compared} onClick={mark}>{busy ? "Сохраняем проверку…" : "Отметить личность проверенной"}<Icon name="check" size={17} /></button></>}
  </div>;
}

function QuickConversationEmpty({ contact, busy, autoSync, showLink, confirm, retry }: { contact: ContactView; busy: boolean; autoSync: boolean; showLink: () => void; confirm: () => void; retry: () => void }) {
  const heading = contact.stage === "quick_queue_pending" ? "Готовим место для нового кота" : contact.stage === "quick_pending" ? "Приглашение отправлено?" : contact.stage === "quick_confirmation" ? "Новый кот просится в стаю" : contact.stage === "quick_expired" ? "Приглашение истекло" : "Собеседник подтвердит знакомство";
  const description = contact.stage === "quick_queue_pending" ? "Сервер ещё не подтвердил подготовку приглашения. Сохранённую попытку можно продолжить." : contact.stage === "quick_pending" ? `Передайте ссылку или покажите QR-код выбранному собеседнику. ${autoSync ? "Ответ появится автоматически, пока приложение работает." : "Нажмите «Синхронизировать», чтобы получить ответ."}` : contact.stage === "quick_confirmation" ? "На ваше приглашение ответили. Подтвердите знакомство, если вы ждёте этого собеседника. Ссылка сама по себе не подтверждает его личность." : contact.stage === "quick_expired" ? "Срок знакомства по этой ссылке закончился. Создайте новое приглашение." : `Ваш ответ передан автоматически. ${autoSync ? "Подтверждение появится, пока приложение на экране." : "Нажмите «Синхронизировать», чтобы получить подтверждение."}`;
  return <div className="empty-conversation"><span className="chat-cat"><CatMark /></span><h2>{heading}</h2><p>{description}</p>{contact.stage === "quick_confirmation" ? <button className="button primary" disabled={busy} onClick={confirm}>Подтвердить знакомство<Icon name="check" size={17} /></button> : contact.stage === "quick_pending" ? <button className="button primary" disabled={busy} onClick={showLink}>Показать ссылку и QR-код<Icon name="mail" size={17} /></button> : contact.stage === "quick_queue_pending" ? <button className="button primary" disabled={busy} onClick={retry}>Продолжить подготовку<Icon name="sync" size={17} /></button> : null}</div>;
}

export default function App() {
  const [background, setBackground] = useState<BackgroundSettings>({ supported: false, enabled: false, interval_minutes: 15 });
  const [notifications, setNotifications] = useState<NotificationSettings>({ supported: false, enabled: false, allowed: false });
  const [profile, setProfile] = useState<ProfileStatus>({ open: false, nickname: "" });
  const [account, setAccount] = useState<AccountView>({login:null,authenticated:false,registered:false,requests:[]});
  const accountFlight = useRef(false);
  const [contacts, setContacts] = useState<ContactView[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [hasMore, setHasMore] = useState(false);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState<string | null>(inNative ? "startup" : null);
  const working = useRef(inNative);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [modal, setModal] = useState<ModalState | null>(null);
  const [pendingLink, setPendingLink] = useState<string | null>(null);
  const pendingUri = useRef<string | null>(null);
  const [autoSync, setAutoSync] = useState(initialAutoSync);
  const [foreground, setForeground] = useState(document.visibilityState === "visible");
  const [autoActive, setAutoActive] = useState(false);
  const [autoRetry, setAutoRetry] = useState(false);
  const alive = useRef(false);
  const generation = useRef(0);
  const userRevision = useRef(0);
  const selectionRevision = useRef(0);
  const contactRefreshRevision = useRef(0);
  const readSettings = useRef({ opened: profile.open, modalOpen: !!modal });
  readSettings.current = { opened: profile.open, modalOpen: !!modal };
  const readBatcher = useRef<VisibleReadBatcher | null>(null);
  const current = useRef({ profile, contacts, selectedId, history, hasMore, autoSync });
  current.current = { profile, contacts, selectedId, history, hasMore, autoSync };
  const scheduler = useRef<ForegroundSyncScheduler | null>(null);
  const syncFlights = useRef(singleFlightSync(api.sync));
  const dirtyContacts = useRef(new Set<string>());
  const dirtyHistory = useRef(new Set<string>());
  const failedContacts = useRef(new Set<string>());
  const selected = contacts.find(contact => contact.id === selectedId);
  const selectedQuick = !!selected && (selected.quick === true || selected.stage.startsWith("quick_"));
  const feed = useRef<HTMLDivElement>(null);
  const compose = useRef<HTMLTextAreaElement>(null);

  function canMarkVisible(contact: string, sequence: number) {
    const root = feed.current;
    if (!alive.current || !inNative || !readSettings.current.opened || readSettings.current.modalOpen || current.current.selectedId !== contact || document.visibilityState !== "visible" || !document.hasFocus() || !root) return false;
    const row = root.querySelector<HTMLElement>(`[data-unread-sequence="${sequence}"]`);
    if (!row || root.clientHeight === 0) return false;
    return hasVisibleMessage(row.getBoundingClientRect(), root.getBoundingClientRect());
  }
  useEffect(() => {
    const batcher = new VisibleReadBatcher({
      canMark: canMarkVisible,
      mark: api.markRead,
      committed: async (contact, sequences) => {
        if (!alive.current) return;
        if (current.current.selectedId === contact) {
          const marked = new Set(sequences);
          storeHistory(current.current.history.map(entry => marked.has(entry.sequence) ? { ...entry, unread: false } : entry), current.current.hasMore);
        }
        try { await refreshContacts(); } catch (reason) { if (alive.current) presentError(reason); }
      },
      failed: () => { if (alive.current) setError("Не удалось сохранить отметку просмотра. Непрочитанные сообщения сохранены; открой беседу ещё раз, чтобы повторить."); },
    });
    readBatcher.current = batcher;
    return () => { batcher.dispose(); if (readBatcher.current === batcher) readBatcher.current = null; };
  }, []);
  useEffect(() => {
    const root = feed.current; const contact = selectedId;
    if (!root || !contact || !profile.open || modal || !foreground) return;
    let frame = 0;
    const scan = () => {
      frame = 0;
      const sequences = [...root.querySelectorAll<HTMLElement>("[data-unread-sequence]")]
        .map(row => Number(row.dataset.unreadSequence)).filter(sequence => canMarkVisible(contact, sequence));
      if (sequences.length) readBatcher.current?.offer(contact, sequences);
    };
    const wake = () => { if (!frame) frame = requestAnimationFrame(scan); };
    const observer = new IntersectionObserver(wake, { root, threshold: [0, 0.01, 0.25, 0.5, 1] });
    root.querySelectorAll("[data-unread-sequence]").forEach(row => observer.observe(row));
    root.addEventListener("scroll", wake, { passive: true });
    window.addEventListener("focus", wake); window.addEventListener("resize", wake);
    document.addEventListener("visibilitychange", wake); wake();
    return () => { observer.disconnect(); if (frame) cancelAnimationFrame(frame); root.removeEventListener("scroll", wake); window.removeEventListener("focus", wake); window.removeEventListener("resize", wake); document.removeEventListener("visibilitychange", wake); };
  }, [selectedId, history, profile.open, modal, foreground]);

  function chooseContact(id: string | null) {
    selectionRevision.current++;
    current.current.selectedId = id;
    setSelectedId(id);
  }
  function storeHistory(next: HistoryEntry[], more: boolean) {
    current.current.history = next; current.current.hasMore = more;
    setHistory(next); setHasMore(more);
  }
  async function refreshContacts() {
    const epoch = generation.current; const refresh = ++contactRefreshRevision.current;
    const next = await api.contacts();
    if (alive.current && generation.current === epoch && contactRefreshRevision.current === refresh) { current.current.contacts = next; setContacts(next); }
    return next;
  }
  async function refreshHistory(id: string) {
    const epoch = generation.current; const selection = selectionRevision.current;
    return appendHistoryTail({
      read: after => api.history(id, after), current: () => current.current.history,
      canContinue: () => alive.current && generation.current === epoch && current.current.selectedId === id && selectionRevision.current === selection && document.visibilityState === "visible",
      append: next => storeHistory(next, current.current.hasMore),
      setHasMore: more => { current.current.hasMore = more; setHasMore(more); },
    });
  }
  function sharedSync(id: string) {
    const handshake = current.current.contacts.find(contact => contact.id === id)?.stage.startsWith("quick_");
    // Durable native progress survives an effect-generation change. UI work remains guarded.
    return syncFlights.current.sync(id).then(report => {
      if (handshake || report.profile_changed) dirtyContacts.current.add(id);
      if (report.received > 0 || report.sent > 0 || report.delivery_changed) { dirtyContacts.current.add(id); dirtyHistory.current.add(id); }
      return report;
    }, reason => {
      dirtyContacts.current.add(id); dirtyHistory.current.add(id);
      throw reason;
    });
  }
  async function refreshAutoProgress(canContinue: () => boolean) {
    const epoch = generation.current; const revision = userRevision.current;
    const valid = () => alive.current && generation.current === epoch && userRevision.current === revision && canContinue();
    if (dirtyContacts.current.size && valid()) {
      const refresh = ++contactRefreshRevision.current;
      const next = await api.contacts();
      if (!valid() || contactRefreshRevision.current !== refresh) return;
      current.current.contacts = next; setContacts(next); dirtyContacts.current.clear();
    }
    const id = current.current.selectedId;
    if (!id || !dirtyHistory.current.has(id) || !valid()) return;
    const selection = selectionRevision.current;
    const complete = await appendHistoryTail({
      read: after => api.history(id, after), current: () => current.current.history,
      canContinue: () => valid() && current.current.selectedId === id && selectionRevision.current === selection,
      append: next => storeHistory(next, current.current.hasMore),
      setHasMore: more => { current.current.hasMore = more; setHasMore(more); },
    });
    if (complete) dirtyHistory.current.delete(id);
  }
  function presentError(reason: unknown) {
    setError(typeof reason === "string" && reason.length < 500 ? reason : "Не получилось выполнить действие. Попробуйте ещё раз.");
  }
  async function run(name: string, action: () => Promise<void>) {
    if (working.current) return;
    const epoch = generation.current;
    userRevision.current++;
    working.current = true; setBusy(name); setError(null); setNotice(null);
    try { await action(); } catch (reason) { if (alive.current && generation.current === epoch) { presentError(reason); if (profile.open && document.visibilityState === "visible") { try { await refreshContacts(); } catch { /* Keep the original operation error. */ } } } }
    finally { if (alive.current && generation.current === epoch) { working.current = false; setBusy(null); scheduler.current?.wake(); } }
  }
  useEffect(() => {
    alive.current = true;
    const epoch = ++generation.current;
    const worker = new ForegroundSyncScheduler({
      contacts: () => current.current.contacts,
      canRun: () => alive.current && generation.current === epoch && inNative && current.current.profile.open && current.current.autoSync && canSyncHere() && !working.current && !accountFlight.current && syncFlights.current.active === 0,
      sync: sharedSync,
      onActivity: id => { if (alive.current && generation.current === epoch) setAutoActive(id !== null); },
      onResult: async (id, report, canContinue) => {
        failedContacts.current.delete(id); setAutoRetry(failedContacts.current.size > 0);
        if (report.received > 0 || report.sent > 0 || report.delivery_changed) { dirtyContacts.current.add(id); dirtyHistory.current.add(id); }
        await refreshAutoProgress(canContinue);
      },
      onError: async (id, canContinue) => {
        failedContacts.current.add(id); setAutoRetry(true);
        // Sync can reject after committing part of the inbox. Keep that progress visible.
        dirtyContacts.current.add(id); dirtyHistory.current.add(id);
        await refreshAutoProgress(canContinue);
      },
    });
    scheduler.current = worker;
    const visibility = () => { setForeground(document.visibilityState === "visible"); worker.setEnabled(inNative && current.current.profile.open && current.current.autoSync && canSyncHere()); };
    const online = () => { if (canSyncHere()) worker.trigger(); };
    document.addEventListener("visibilitychange", visibility);
    window.addEventListener("online", online);
    window.addEventListener("pageshow", online);
    visibility();
    return () => { alive.current = false; generation.current++; worker.dispose(); if (scheduler.current === worker) scheduler.current = null; document.removeEventListener("visibilitychange", visibility); window.removeEventListener("online", online); window.removeEventListener("pageshow", online); };
  }, []);

  useEffect(() => {
    if (!inNative) return;
    let mounted = true;
    let unlisten: (() => void) | null = null;
    const progress = () => {
      if (!mounted) return;
      for (const contact of current.current.contacts) dirtyContacts.current.add(contact.id);
      if (current.current.selectedId) dirtyHistory.current.add(current.current.selectedId);
      const available = () => mounted && alive.current && current.current.profile.open && document.visibilityState === "visible" && !working.current;
      if (available()) void refreshAutoProgress(available).catch(() => {});
      scheduler.current?.wake();
    };
    void listen("profile-progress", progress).then(stop => { if (mounted) unlisten = stop; else stop(); }).catch(() => {});
    const visible = () => { if (document.visibilityState === "visible") progress(); };
    document.addEventListener("visibilitychange", visible);
    return () => { mounted = false; unlisten?.(); document.removeEventListener("visibilitychange", visible); };
  }, []);
  useEffect(() => {
    if (!inNative) return;
    let mounted = true;
    let unlisten: (() => void) | null = null;
    function stageLink(value: string) {
      if (!mounted) return;
      try {
        const link = normalizeInvitationLink(value);
        if (pendingUri.current === link) return;
        pendingUri.current = link; setPendingLink(link);
        if (!current.current.profile.open) setNotice("Получено приглашение. Откройте профиль, чтобы принять его.");
      } catch { setError("Ссылка-приглашение не подходит. Попросите собеседника прислать её целиком."); }
    }
    void (async () => {
      try {
        const stop = await listen<string>("invitation-link", event => stageLink(event.payload));
        if (!mounted) { stop(); return; }
        unlisten = stop;
        const link = await api.takePendingInvitation();
        if (link) stageLink(link);
      } catch { /* Pasting a link remains available if platform link delivery fails. */ }
    })();
    return () => { mounted = false; unlisten?.(); };
  }, []);
  useEffect(() => {
    if (!pendingLink || !profile.open || busy || modal) return;
    setError(null); setNotice(null); setModal({ kind: "accept", link: pendingLink }); setPendingLink(null);
  }, [pendingLink, profile.open, busy, modal]);
  useEffect(() => {
    scheduler.current?.setEnabled(inNative && profile.open && autoSync && (desktopSync || foreground));
    scheduler.current?.wake();
  }, [profile.open, autoSync, foreground, contacts]);
  useEffect(() => {
    if (!inNative) return;
    let mounted = true;
    api.status().then(async status => {
      if (!mounted) return;
      setProfile(status);
      if (status.open) await refreshContacts();
    }).catch(reason => { if (mounted) presentError(reason); }).finally(() => { if (mounted) { working.current = false; setBusy(null); } });
    return () => { mounted = false; };
  }, []);

  useEffect(() => {
    if (!inNative) return;
    let mounted=true;
    const refresh=() => { if (!working.current && document.visibilityState === "visible") Promise.all([api.notificationSettings(), api.backgroundSettings()]).then(([next, bg]) => { if (mounted) { setNotifications(next); setBackground(bg); } }).catch(() => {}); };
    refresh(); window.addEventListener("focus", refresh); document.addEventListener("visibilitychange", refresh);
    return () => { mounted=false; window.removeEventListener("focus", refresh); document.removeEventListener("visibilitychange", refresh); };
  }, [busy]);
  useEffect(() => {
    if (!inNative) return;
    const update=() => { void api.notificationView(profile.open && !modal && document.visibilityState === "visible" && document.hasFocus() ? selectedId : null).catch(() => {}); };
    update(); window.addEventListener("focus", update); window.addEventListener("blur", update); document.addEventListener("visibilitychange", update);
    return () => { window.removeEventListener("focus", update); window.removeEventListener("blur", update); document.removeEventListener("visibilitychange", update); };
  }, [profile.open, selectedId, modal]);
  function toggleBackground() {
    const enable = !background.enabled;
    void run("background", async () => {
      const next = await api.setBackground(enable); setBackground(next);
      setNotice(next.enabled ? "Фоновое получение включено. Первая проверка примерно через минуту, затем — раз в 15 минут или реже. Android может задержать запуск." : "Фоновое получение выключено. Синхронизация на экране продолжает работать.");
    });
  }
  function toggleNotifications() {
    const enable=!notifications.enabled;
    void run("notifications", async () => {
      const next=await api.setNotifications(enable); setNotifications(next);
      setNotice(enable ? !next.allowed ? "Уведомления отключены в Android. Разрешить их можно в системных настройках приложения." : "Уведомления включены. Имя и текст сообщения будут скрыты." : "Уведомления выключены.");
    });
  }
  function submitBackup(mode: BackupMode, password: string) {
    void run("backup", async () => {
      const done = await profileBackup(mode, password);
      if (!done) return;
      if (mode === "restore") {
        const next = await api.status(); current.current.profile = next; setProfile(next); await refreshContacts();
      }
      setModal(null);
      setNotice(mode === "export" ? "Копия сохранена. Теперь проверь её с тем же паролем и сохрани отдельно от устройства." : mode === "verify" ? "Копия проверена: пароль и данные читаются. Текущий профиль не изменён." : "Профиль восстановлен. Старые беседы доступны как архив; для общения создай новое знакомство.");
    });
  }
  function openProfile() { void run("open", async () => { const epoch = generation.current; const next = await api.open(); if (!alive.current || generation.current !== epoch) return; current.current.profile = next; setProfile(next); await refreshContacts(); }); }
  function saveNickname(value: string) {
    void run("nickname", async () => {
      const next = await api.setNickname(value);
      current.current.profile = next; setProfile(next); setModal(null);
      scheduler.current?.wake();
      setNotice("Ник сохранён. Собеседники увидят его после синхронизации.");
    });
  }
  function saveAlias(value: string) {
    if (modal?.kind !== "alias") return;
    const contact = modal.contact;
    void run("alias", async () => { await api.setContactAlias(contact, value); await refreshContacts(); setModal(null); setNotice("Название контакта сохранено только на этом устройстве."); });
  }
  function selectContact(contact: ContactView) {
    if (working.current || contact.id === selectedId) return;
    void run("history", async () => {
      const epoch = generation.current;
      const next = await api.history(contact.id, 0);
      if (!alive.current || generation.current !== epoch) return;
      chooseContact(contact.id); storeHistory(next, next.length === 100); setDraft("");
    });
  }
  function showExport(id: string) { void run("export", async () => {
    const contact = current.current.contacts.find(item => item.id === id);
    if (contact?.quick || contact?.stage.startsWith("quick_")) setModal({ kind: "quick_export", data: await api.exportQuick(id) });
    else setModal({ kind: "export", data: await api.exportInvitation(id) });
  }); }
  function showVerification(id: string) { void run("verification", async () => { setModal({ kind: "verify", contact: id, data: await api.verification(id) }); }); }
  function markVerified() {
    if (modal?.kind !== "verify") return;
    const snapshot = modal;
    void run("verify", async () => { await api.markVerified(snapshot.contact, snapshot.data.fingerprint); await refreshContacts(); setModal(null); setNotice("Проверка личности сохранена на этом устройстве."); });
  }
  function confirmQuick() {
    if (modal?.kind !== "confirm") return;
    const id = modal.contact;
    void run("confirm", async () => { await api.confirmQuick(id); await refreshContacts(); setModal(null); dirtyHistory.current.add(id); scheduler.current?.trigger(id); setNotice("Знакомство подтверждено. Личность можно проверить отдельно."); });
  }
  function submitQuick(fields: { link: string; relay: string; ticket: string }) {
    if (modal?.kind !== "create" && modal?.kind !== "accept") return;
    const kind = modal.kind;
    void run("quick", async () => {
      const existing = new Set(current.current.contacts.map(contact => contact.id));
      let data: QuickInvitationExport;
      try { data = kind === "create" ? account.authenticated ? await api.createAccountLink() : await api.createQuick(fields.relay, fields.ticket) : await api.acceptQuick(fields.link); }
      catch (reason) {
        try {
          const next = await refreshContacts();
          const pending = next.find(contact => !existing.has(contact.id) && contact.stage.startsWith("quick_"));
          if (pending) { chooseContact(pending.id); storeHistory([], false); setDraft(""); setModal(null); }
        } catch { /* Retain the original error. */ }
        throw reason;
      }
      pendingUri.current = null;
      chooseContact(data.contact); storeHistory([], false); setDraft(""); await refreshContacts();
      setModal(kind === "create" ? { kind: "quick_export", data } : null);
      scheduler.current?.trigger(data.contact);
      if (kind === "accept") setNotice("Приглашение принято. Ждём подтверждение собеседника.");
    });
  }
  function retryProvision(ticket: string | null) {
    if (modal?.kind !== "retry") return;
    const id = modal.contact;
    void run("provision", async () => {
      if (modal.quick) {
        const data = await api.provisionQuick(id, ticket);
        await refreshContacts(); chooseContact(data.contact); setModal({ kind: "quick_export", data });
      } else {
        const data = await api.provision(id, ticket);
        await refreshContacts(); chooseContact(data.contact); setModal({ kind: "export", data });
      }
    });
  }
  function deleteContact() {
    if (modal?.kind !== "delete") return;
    const id = modal.contact;
    void run("delete", async () => {
      await api.deleteContact(id);
      // Invalidate late history callbacks before changing the visible list.
      if (current.current.selectedId === id) { chooseContact(null); storeHistory([], false); setDraft(""); }
      current.current.contacts = current.current.contacts.filter(contact => contact.id !== id);
      setContacts(current.current.contacts);
      dirtyContacts.current.delete(id); dirtyHistory.current.delete(id); failedContacts.current.delete(id);
      await refreshContacts(); setModal(null); setNotice("Удалено на этом устройстве.");
    });
  }
  function submitInvitation(fields: { invitation: string; fingerprint: string; relay: string; ticket: string }) {
    if (!modal || (modal.kind !== "legacy_create" && modal.kind !== "legacy_accept" && modal.kind !== "complete")) return;
    const current = modal;
    void run("invitation", async () => {
      if (current.kind === "complete") {
        await api.completeOffer(current.contact, fields.invitation, fields.fingerprint);
        await refreshContacts(); setModal(null); setNotice("Собеседник подтверждён. Первое «мяу» за вами.");
      } else {
        const existing = new Set(contacts.map(contact => contact.id));
        let data: InvitationExport;
        try {
          data = current.kind === "legacy_create" ? await api.createOffer(fields.relay, fields.ticket) : await api.acceptOffer(fields.invitation, fields.fingerprint, fields.relay, fields.ticket);
        } catch (reason) {
          // The native worker saves a queue proposal before HTTP. Resume that
          // contact instead of submitting a second proposal with the same ticket.
          try {
            const next = await refreshContacts();
            const pending = next.find(contact => !existing.has(contact.id) && contact.stage === "queue_pending");
            if (pending) {
              chooseContact(pending.id); storeHistory([], false); setDraft("");
              setModal({ kind: "retry", contact: pending.id });
            }
          } catch { /* Preserve the original operation error. */ }
          throw reason;
        }
        chooseContact(data.contact); storeHistory([], false); setDraft(""); setModal({ kind: "export", data });
        await refreshContacts();
      }
    });
  }
  async function accountAction(action:()=>Promise<AccountView>){
    await run("account",async()=>{setAccount(await action());await refreshContacts();});
  }
  function openAccount(){void run("account",async()=>{setAccount(await api.account());setModal({kind:"account"});});}
  useEffect(()=>{
    let disposed=false;
    const poll=async()=>{
      if(!inNative||!current.current.profile.open||!current.current.autoSync||!canSyncHere()||working.current||accountFlight.current||syncFlights.current.active>0)return;
      accountFlight.current=true;
      const epoch=generation.current;
      try{const view=await api.syncAccount();if(!disposed&&alive.current&&epoch===generation.current){setAccount(view);await refreshContacts();}}
      catch {/* Saved handshakes retry on the next pass; existing chats keep working. */}
      finally{accountFlight.current=false;}
    };
    const timer=window.setInterval(()=>void poll(),10000);
    void poll();
    return()=>{disposed=true;window.clearInterval(timer);};
  },[profile.open,autoSync]);
  function sendMessage(event?: FormEvent) {
    event?.preventDefault();
    if (!selected || !selected.can_send || !draft.trim()) return;
    const id = selected.id; const text = draft;
    if (new TextEncoder().encode(text).byteLength > MAX_TEXT_BYTES) {
      setError("Сообщение слишком длинное: предел — 24 KiB в UTF-8.");
      return;
    }
    void run("send", async () => { const epoch = generation.current; await api.enqueue(id, text); if (!alive.current || generation.current !== epoch) return; setDraft(""); dirtyHistory.current.add(id); scheduler.current?.trigger(id); if (await refreshHistory(id)) dirtyHistory.current.delete(id); compose.current?.focus(); });
  }
  function syncContact() {
    if (!selected || !canSyncStage(selected.stage)) return;
    const id = selected.id;
    void run("sync", async () => {
      let syncError: unknown;
      let report;
      try { report = await sharedSync(id); } catch (reason) { syncError = reason; }
      dirtyHistory.current.add(id); await refreshContacts(); if (await refreshHistory(id)) dirtyHistory.current.delete(id);
      if (syncError) throw syncError;
      if (report) setNotice(`Сверились с сервером: отправлено ${report.sent}, получено ${report.received}.`);
    });
  }
  function loadMore() {
    if (!selected || !history.length) return;
    const id = selected.id; const after = history[history.length - 1].sequence;
    void run("more", async () => { const selection = selectionRevision.current; const next = await api.history(id, after); if (current.current.selectedId !== id || selectionRevision.current !== selection || !alive.current) return; storeHistory(mergeHistory(current.current.history, next), next.length === 100); });
  }
  const disabled = !!busy;
  const opened = profile.open;
  const available = inNative;
  const statusLabel = busy === "startup" ? "Проверяем профиль…" : opened ? "Профиль открыт" : "Профиль закрыт";
  const autoLabel = !autoSync ? "Ручной режим" : !foreground && !desktopSync ? "Авто на паузе" : autoActive ? "Сверяемся с сервером…" : autoRetry ? "Повторим связь автоматически" : "Авто · каждые 10 секунд";
  const syncMode = <SyncMode enabled={autoSync} status={autoLabel} toggle={() => { const enabled = !current.current.autoSync; current.current.autoSync = enabled; setAutoSync(enabled); try { localStorage.setItem(AUTO_SYNC_SETTING, String(enabled)); } catch { /* Keep the session choice when webview storage is unavailable. */ } scheduler.current?.setEnabled(inNative && opened && enabled && canSyncHere()); }} />;

  const settingsControls = <>{opened && syncMode}{opened && notifications.supported && <div className="notification-mode"><div className="sync-mode-heading"><button className="sync-mode-toggle" type="button" role="switch" aria-label="Уведомления о сообщениях" aria-checked={notifications.enabled} disabled={disabled} onClick={toggleNotifications}><span className="switch-track"><span /></span></button><span>Уведомления</span></div><p>{notifications.enabled ? notifications.allowed ? "Без имени и текста сообщения" : "Отключены в настройках Android" : "Выключены · можно включить"}</p><p className="notification-limit">{background.enabled ? "В фоне — по расписанию Android" : "Получение — пока приложение на экране"}</p></div>}{opened && background.supported && <div className="notification-mode"><div className="sync-mode-heading"><button className="sync-mode-toggle" type="button" role="switch" aria-label="Фоновое получение сообщений" aria-checked={background.enabled} disabled={disabled} onClick={toggleBackground}><span className="switch-track"><span /></span></button><span>Фоновое получение</span></div><p>{background.enabled ? "Примерно раз в 15 минут или реже" : "Выключено · можно включить"}</p><p className="notification-limit">Проверка профиля при закрытом интерфейсе</p></div>}</>;

  return <div className={`app-shell ${selected ? "show-conversation" : "show-conversations"}`}>
    <aside className="sidebar">
      <header className="brand"><span className="brand-icon"><CatMark /></span><div><span className="brand-name">КотоПизделка<span className="brand-period">.</span></span><span className="brand-tagline">Своя стая. Свои правила.</span></div></header>
      <div className="mobile-only"><Alerts error={error} notice={notice} clearError={() => setError(null)} clearNotice={() => setNotice(null)} /></div>
      {opened && <button className="account-entry" disabled={disabled} onClick={openAccount}>{account.authenticated ? `@${account.login}` : "Войти в стаю"}{account.requests.filter(r=>r.incoming&&r.status==="pending").length>0 && <span className="unread-badge">{account.requests.filter(r=>r.incoming&&r.status==="pending").length}</span>}</button>}
      <div className="sidebar-section-heading"><span>РАЗГОВОРЫ</span><span className="count">{contacts.length}</span></div>
      <button className="new-chat-button" disabled={!opened || disabled} onClick={() => { if(account.authenticated){openAccount();}else{setError(null); setModal({ kind: "create" });} }}><span className="plus-box"><Icon name="plus" size={18} /></span><span>{account.authenticated ? "Добавить кота" : "Пригласить в стаю"}</span><Icon name="arrow" size={15} /></button>
      <div className="contacts">
        {contacts.map(contact => <button key={contact.id} className={`contact-row ${selectedId === contact.id ? "selected" : ""}`} onClick={() => selectContact(contact)} disabled={disabled} aria-pressed={selectedId === contact.id}>
          <span className="contact-avatar"><CatMark /></span><span className="contact-details"><span className="contact-name" title={contactName(contact)}>{contactName(contact)}</span>{(contact.alias || contact.nickname) && <span className="contact-code">{shortId(contact.id)}</span>}<span className="contact-stage">{stageText[contact.stage]}</span></span>{contact.unread > 0 && <span className="unread-badge" aria-label={`Непрочитанных сообщений: ${contact.unread}`} title={`Непрочитанных сообщений: ${contact.unread}`}>{contact.unread > 99 ? "99+" : contact.unread}</span>}
        </button>)}
        {!contacts.length && <div className="sidebar-empty"><span className="little-orbit"><Icon name={opened ? "mail" : "lock"} size={21} /></span><p>{opened ? "Стая пока не собралась" : "Разговоры появятся здесь"}</p><span className="sidebar-empty-description">{opened ? "Один кот — хорошо. Два — уже чат." : "Сначала откройте свой профиль."}</span>{!opened && <div className="mobile-only mobile-profile"><button className="button primary open-profile" onClick={openProfile} disabled={!available || disabled}><Icon name="lock" size={18} />{busy === "open" ? "Открываем профиль…" : "Открыть профиль"}<Icon name="arrow" size={18} /></button><button className="button secondary" disabled={!available || disabled} onClick={() => { setError(null); setModal({kind:"backup",mode:"restore"}); }}>Восстановить копию</button><p className="profile-help">{!inNative ? "Профиль открывается в приложении." : "Первый запуск создаст профиль на этом устройстве."}</p></div>}</div>}
      </div>
      <div className="sidebar-bottom">{opened && <><div className="desktop-settings">{settingsControls}</div><button className="button secondary full settings-button" disabled={disabled} onClick={() => setModal({kind:"settings"})}><Icon name="settings" size={18} />Настройки<Icon name="arrow" size={16} /></button></>}<button className="join-link" onClick={() => { setError(null); setModal({ kind: "accept" }); }} disabled={!opened || disabled}><Icon name="mail" size={17} />У меня есть приглашение<Icon name="arrow" size={15} /></button><button className="profile-strip" type="button" disabled={!opened || disabled} onClick={() => { setError(null); setModal({ kind: "profile" }); }} aria-label="Мой ник"><span className={`status-dot ${opened ? "open" : ""}`} /><span>{opened ? profile.nickname || "Придумать себе ник" : statusLabel}</span><Icon name="edit" size={14} /></button><span className="version">Лаборатория котов · v0.2.10</span></div>
    </aside>
    <main className="main-panel">
      <header className="conversation-header"><div className="conversation-title">{selected && <button className="icon-button mobile-only back-button" disabled={disabled} onClick={() => { chooseContact(null); storeHistory([], false); setDraft(""); }} aria-label="Назад к разговорам" title="Назад к разговорам"><Icon name="back" /></button>}<span className="header-symbol"><Icon name={selected ? "mail" : "lock"} size={20} /></span><div><h1>{selected ? contactName(selected) : "Личные разговоры"}</h1><p>{selected ? stageText[selected.stage] : "Место, где можно быть собой. И немного котом."}</p></div></div><div className="header-actions">{selected && <button className="icon-button" disabled={disabled} onClick={() => { setError(null); setModal({ kind: "alias", contact: selected.id, alias: selected.alias, nickname: selected.nickname }); }} title="Название контакта" aria-label="Название контакта"><Icon name="edit" /></button>}{selected && <button className="icon-button delete-contact" disabled={disabled} onClick={() => { setError(null); setModal({ kind: "delete", contact: selected.id, invitation: !selected.can_send && selected.stage !== "archived" }); }} title={(selected.can_send || selected.stage === "archived") ? "Удалить беседу" : "Удалить приглашение"} aria-label={(selected.can_send || selected.stage === "archived") ? "Удалить беседу" : "Удалить приглашение"}><Icon name="trash" /></button>}{selected && ((!selectedQuick && selected.stage !== "queue_pending") || selected.stage === "quick_pending") && <button className="icon-button" disabled={disabled} onClick={() => showExport(selected.id)} title="Показать сохранённое приглашение" aria-label="Показать сохранённое приглашение"><Icon name="mail" /></button>}{selected && canSyncStage(selected.stage) && <button className="button secondary compact" disabled={disabled} onClick={syncContact} title="Синхронизировать" aria-label={busy === "sync" ? "Синхронизируем…" : "Синхронизировать"}><Icon name="sync" size={17} />{busy === "sync" ? "Синхронизируем…" : "Синхронизировать"}</button>}{opened && <button className="icon-button" disabled={disabled} onClick={() => setModal({kind:"settings"})} title="Настройки" aria-label="Настройки"><Icon name="settings" /></button>}<span className="lab-badge">ЛИЧНЫЙ ПРОТОТИП</span></div></header>
      <Alerts error={error} notice={notice} clearError={() => setError(null)} clearNotice={() => setNotice(null)} />
      {selected && selectedQuick && ["ready", "quick_confirmation", "quick_waiting"].includes(selected.stage) && <div className="trust-strip"><span><Icon name={selected.verified ? "check" : "lock"} size={15} />{selected.verified ? "Личность проверена" : "Личность не проверена"}</span><button className="button text-button" disabled={disabled} onClick={() => showVerification(selected.id)}>Проверить собеседника</button></div>}
      {!selected ? <div className="welcome-view">
        <div className="welcome-content"><span className="welcome-eyebrow"><span /> МУРЧАТЬ РАЗРЕШАЕТСЯ</span><CatIllustration /><h2>{opened ? <>Соберите свою стаю<span className="amber">.</span></> : <>Своя стая.<br />Свои разговоры<span className="amber">.</span></>}</h2><p className="welcome-description">{opened ? "Здесь пока тихо. Даже коты не спорят. Пригласите собеседника или примите его приглашение." : "Личные сообщения для близких людей. Без телефонных номеров, списков знакомств и лишней суеты."}</p>
          {opened ? <div className="welcome-buttons"><button className="button primary" disabled={disabled} onClick={() => { setError(null); setModal({ kind: "create" }); }}><Icon name="plus" size={18} />Создать приглашение</button><button className="button text-button" disabled={disabled} onClick={() => { setError(null); setModal({ kind: "accept" }); }}>Принять приглашение<Icon name="arrow" size={17} /></button></div> : <><button className="button primary open-profile" onClick={openProfile} disabled={!available || disabled}><Icon name="lock" size={18} />{busy === "open" ? "Открываем профиль…" : "Открыть профиль"}<Icon name="arrow" size={18} /></button><button className="button secondary" disabled={!available || disabled} onClick={() => { setError(null); setModal({kind:"backup",mode:"restore"}); }}>Восстановить копию</button><p className="profile-help">{!inNative ? "Профиль открывается в приложении." : busy === "startup" ? "Проверяем возможность открытия на этом устройстве."  : "Первый запуск создаст профиль на этом устройстве."}</p></>}
        </div><div className="welcome-footer"><span className="small-paw">✦</span> Коты не читают ваши сообщения. Им всё равно нужен сон.</div>
      </div> : <>
        <div className="message-feed" ref={feed}>{history.length === 0 ? selected.stage.startsWith("quick_") ? <QuickConversationEmpty contact={selected} busy={disabled} autoSync={autoSync} showLink={() => showExport(selected.id)} confirm={() => { setError(null); setModal({ kind: "confirm", contact: selected.id }); }} retry={() => { if (selected) { setError(null); setModal({ kind: "retry", contact: selected.id, quick: true }); } }} /> : <div className="empty-conversation"><span className="chat-cat"><CatMark /></span><h2>{selected.stage === "queue_pending" ? "Очередь ещё не готова" : selected.stage === "offer_pending" ? "Приглашение ждёт ответа" : selected.stage === "waiting_first_message" ? "Первое «мяу» — от собеседника" : "Начнём с «мяу»?"}</h2><p>{selected.stage === "queue_pending" ? "Сервер ещё не подтвердил создание очереди. Приглашение сохранено в профиле; повторите попытку, чтобы продолжить." : selected.stage === "offer_pending" ? "Передайте приглашение и отдельно его отпечаток. Получив ответ, завершите знакомство." : selected.stage === "waiting_first_message" ? autoSync ? "Отправьте собеседнику ответ на приглашение. Его первое сообщение появится автоматически, пока приложение открыто на экране." : "Отправьте собеседнику ответ на приглашение. Он должен прислать первое сообщение. Нажмите «Синхронизировать», чтобы его получить." : autoSync ? "Разговор готов. Напишите сообщение — сохраним его и автоматически отправим на сервер." : "Разговор уже готов. Напишите сообщение — оно сохранится в очереди до синхронизации."}</p>{selected.stage === "queue_pending" ? <button className="button primary" disabled={disabled} onClick={() => { setError(null); setModal({ kind: "retry", contact: selected.id }); }}>Повторить создание очереди<Icon name="sync" size={17} /></button> : selected.stage === "offer_pending" ? <div className="welcome-buttons"><button className="button primary" disabled={disabled} onClick={() => { setError(null); setModal({ kind: "complete", contact: selected.id }); }}>У меня есть ответ<Icon name="arrow" size={17} /></button><button className="button secondary" disabled={disabled} onClick={() => showExport(selected.id)}>Показать приглашение</button></div> : selected.stage === "waiting_first_message" ? <button className="button secondary" disabled={disabled} onClick={() => showExport(selected.id)}>Показать мой ответ<Icon name="mail" size={16} /></button> : null}</div> : <><div className="history-start"><span />НАЧАЛО РАЗГОВОРА<span /></div>{history.map(entry => <article className={`message-row ${entry.direction}`} key={entry.sequence} data-unread-sequence={entry.direction === "incoming" && entry.unread ? entry.sequence : undefined}><span className="message-avatar"><CatMark /></span><div className="message-bubble"><span className="message-author">{entry.direction === "outgoing" ? selected.stage === "archived" ? "Вы · архив" : `Вы · ${entry.delivery === "delivered" ? "получено собеседником" : entry.delivery === "server" ? "на сервере" : "в очереди"}` : contactName(selected)}</span><p>{entry.text}</p></div></article>)}{hasMore && <button className="button secondary load-more" onClick={loadMore} disabled={disabled}>Загрузить следующие сообщения<Icon name="arrow" size={16} /></button>}</>}</div>
        <div className="compose-area">{selected.stage === "archived" && <p className="archive-note">Это архив восстановленной беседы. Для новых сообщений добавь собеседника заново.</p>}<div className="delivery-note"><span className="status-dot" /><span>{autoSync ? "Сообщение сохраняется здесь и отправляется автоматически, пока приложение работает." : "Сообщение сохраняется здесь. Для обмена с сервером нажмите «Синхронизировать»."}</span></div><form className="composer" onSubmit={sendMessage}><textarea ref={compose} value={draft} onChange={event => setDraft(event.target.value)} disabled={disabled || !selected.can_send} rows={2} maxLength={MAX_TEXT_BYTES} placeholder={selected.can_send ? "Что будем мяукать?" : selected.stage === "queue_pending" ? "Сначала завершите создание очереди" : selected.stage === "offer_pending" ? "Сначала завершите обмен приглашениями" : selected.stage.startsWith("quick_") ? "Сначала завершите знакомство" : "Ждём первое сообщение от собеседника"} aria-label="Сообщение" onKeyDown={event => { if (event.key === "Enter" && !event.shiftKey && !event.nativeEvent.isComposing && !window.matchMedia("(max-width: 700px)").matches) { event.preventDefault(); sendMessage(); } }} /><button className="send-button" type="submit" disabled={disabled || !selected.can_send || !draft.trim()} aria-label="Сохранить сообщение в очереди" title="Сохранить сообщение в очереди"><Icon name="send" size={22} /></button></form><div className="composer-hint"><span className="desktop-compose-hint">Enter — в очередь · Shift + Enter — новая строка</span><span className="mobile-only mobile-compose-hint">Стрелка — в очередь · Enter — новая строка</span><span>У каждого разговора — свои ключи <Icon name="lock" size={12} /></span></div></div>
      </>}
      <footer className="app-bottom"><span><span className="tiny-dot" />Локальный профиль · {opened ? "открыт" : "закрыт"}</span><span>Сделано людьми. Одобрено котами <CatMark /></span></footer>
    </main>
    {modal && <Modal quickInvitation={modal.kind === "quick_export"} title={modal.kind === "backup" ? modal.mode === "export" ? "Сохранить профиль" : modal.mode === "verify" ? "Проверить копию" : "Восстановить профиль" : modal.kind === "settings" ? "Настройки" : modal.kind === "account" ? "Аккаунт стаи" : modal.kind === "profile" ? "Как тебя зовут, кот?" : modal.kind === "alias" ? "Название контакта" : modal.kind === "create" || modal.kind === "legacy_create" ? "Пригласить в стаю" : modal.kind === "accept" || modal.kind === "legacy_accept" ? "Принять приглашение" : modal.kind === "complete" ? "Завершить знакомство" : modal.kind === "confirm" ? "Принять нового кота" : modal.kind === "verify" ? "Проверить собеседника" : modal.kind === "delete" ? modal.invitation ? "Удалить приглашение?" : "Удалить беседу?" : modal.kind === "retry" ? "Дать очереди ещё шанс" : "Передать приглашение"} busy={disabled} onClose={() => { pendingUri.current = null; setModal(null); setError(null); }}>
      {error && <div className="modal-error" role="alert">{error}</div>}
      {modal.kind === "backup" ? <ProfileBackupForm mode={modal.mode} busy={disabled} submit={submitBackup} /> : modal.kind === "settings" ? <div className="modal-body settings-panel"><p className="form-intro">Как твоя стая получает сообщения.</p>{settingsControls}<div className="backup-settings"><h3>Резервная копия профиля</h3><p className="field-hint">Ключ аккаунта и история в файле с паролем, отдельно от устройства.</p><button className="button secondary full" disabled={disabled} onClick={() => {setError(null);setModal({kind:"backup",mode:"export"});}}>Сохранить копию</button><button className="button secondary full" disabled={disabled} onClick={() => {setError(null);setModal({kind:"backup",mode:"verify"});}}>Проверить копию</button></div></div> : modal.kind === "account" ? <AccountsPanel view={account} busy={disabled} authenticate={(login,password,register)=>void accountAction(()=>api.authenticateAccount(login,password,register))} find={async login=>(await api.findAccount(login)).login} add={login=>void accountAction(()=>api.addAccount(login))} decide={(id,accept)=>void accountAction(()=>api.decideAccount(id,accept))} logout={()=>void accountAction(api.logoutAccount)} refresh={()=>void accountAction(api.syncAccount)} invite={()=>setModal({kind:"create"})} /> : modal.kind === "profile" ? <NameForm value={profile.nickname} busy={disabled} submit={saveNickname} /> : modal.kind === "alias" ? <NameForm value={modal.alias} peer={modal.nickname} busy={disabled} submit={saveAlias} /> : modal.kind === "delete" ? <div className="modal-body"><p className="form-intro">{modal.invitation ? "Приглашение исчезнет из списка на этом устройстве. Его локальные ключи будут удалены." : "История, неотправленные сообщения и ключи этой беседы будут удалены на этом устройстве. У собеседника переписка останется."}</p><p className="field-hint">Отменить удаление нельзя. Чтобы снова поговорить, понадобится новое приглашение.</p><div className="delete-actions"><button className="button secondary" disabled={disabled} onClick={() => setModal(null)}>Оставить</button><button className="button danger" disabled={disabled} onClick={deleteContact}><Icon name="trash" size={17} />{disabled ? "Удаляем…" : "Удалить"}</button></div></div> : modal.kind === "export" ? <ExportPanel data={modal.data} /> : modal.kind === "quick_export" ? <QuickExportPanel data={modal.data} /> : modal.kind === "retry" ? <RetryForm busy={disabled} quick={modal.quick} automatic={!!modal.quick && account.authenticated} submit={retryProvision} /> : modal.kind === "verify" ? <VerificationPanel key={modal.contact} data={modal.data} busy={disabled} mark={markVerified} /> : modal.kind === "confirm" ? <div className="modal-body"><p className="form-intro">На приглашение ответил тот, кто получил вашу ссылку. Подтвердите знакомство, если вы ожидаете этого собеседника.</p><div className="form-note"><Icon name="lock" size={17} /><span>Личность пока не проверена. После знакомства можно сравнить код через независимый канал.</span></div><button className="button primary full" disabled={disabled} onClick={confirmQuick}>{disabled ? "Подтверждаем знакомство…" : "Подтвердить знакомство"}<Icon name="check" size={17} /></button></div> : modal.kind === "create" || modal.kind === "accept" ? <QuickInvitationForm account={account.authenticated} key={modal.kind === "accept" ? modal.link ?? "paste" : "create"} kind={modal.kind} busy={disabled} initialLink={modal.kind === "accept" ? modal.link : undefined} submit={submitQuick} legacy={() => { setError(null); setModal({ kind: modal.kind === "create" ? "legacy_create" : "legacy_accept" }); }} scan={modal.kind === "accept" && /Android/i.test(navigator.userAgent) ? api.scanInvitation : undefined} /> : <InvitationForm kind={modal.kind === "legacy_create" ? "create" : modal.kind === "legacy_accept" ? "accept" : "complete"} busy={disabled} submit={submitInvitation} />}
    </Modal>}
  </div>;
}

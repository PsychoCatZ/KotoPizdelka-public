import { useEffect, useMemo, useRef, useState } from "react";
import type { FormEvent } from "react";
import { Icon } from "./Art";
import { invitationQr, invitationQrDisplaySize, MAX_INVITATION_LINK_LENGTH, normalizeInvitationLink } from "./invitationLink";

export interface QuickInvitationData { contact: string; link: string; expires_at: number }

export function QuickInvitationForm({ kind, busy, initialLink = "", submit, legacy, scan, account = false }: {
  kind: "create" | "accept";
  busy: boolean;
  account?: boolean;
  initialLink?: string;
  submit: (fields: { link: string; relay: string; ticket: string }) => void;
  legacy: () => void;
  scan?: () => Promise<string | null>;
}) {
  const [link, setLink] = useState(initialLink);

  const [ticket, setTicket] = useState("");
  const [linkError, setLinkError] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  async function scanCode() {
    if (!scan || scanning) return;
    setScanning(true); setLinkError(null);
    try { const scanned = await scan(); if (scanned) setLink(normalizeInvitationLink(scanned)); }
    catch { setLinkError("Не получилось прочитать приглашение. Попробуйте ещё раз или вставьте ссылку."); }
    finally { setScanning(false); }
  }
  function onSubmit(event: FormEvent) {
    event.preventDefault();
    try {
      submit({ link: kind === "accept" ? normalizeInvitationLink(link) : "", relay: "", ticket: ticket.trim().toLowerCase() });
      setLinkError(null);
    } catch { setLinkError("Вставьте ссылку-приглашение КотоПизделки целиком."); }
  }
  return <form className="modal-body" autoComplete="off" onSubmit={onSubmit}>
    <p className="form-intro">{kind === "create" ? "Одна ссылка или QR-код — и новый кот найдёт вашу стаю. После принятия вы подтвердите знакомство здесь." : "Вставьте ссылку от собеседника. Ответ отправится автоматически; остаётся дождаться его подтверждения."}</p>
    {kind === "accept" ? <>
      {scan && <button className="button secondary full scan-invitation" type="button" disabled={busy || scanning} onClick={() => void scanCode()}>{scanning ? "Смотрим на QR-код…" : "Сканировать QR-код"}</button>}
      <label>Ссылка-приглашение<textarea className="artifact-input" value={link} onChange={event => { setLink(event.target.value); setLinkError(null); }} rows={4} maxLength={MAX_INVITATION_LINK_LENGTH} required disabled={busy || scanning} spellCheck={false} autoCapitalize="off" placeholder="kotopizdelka://invite#…" aria-label="Ссылка-приглашение" /></label>
      {linkError && <p className="inline-error" role="alert">{linkError}</p>}
    </> : account ? <div className="form-note"><Icon name="check" size={17} /><span>Создадим приглашение через твой аккаунт. Билет и адрес сервера вводить не нужно.</span></div> : <div className="invite-server">
      <p className="field-hint">Сервер стаи уже настроен. Адрес передавать не нужно.</p>
      <label>Билет для приглашения<input type="password" value={ticket} onChange={event => setTicket(event.target.value)} pattern="[a-fA-F0-9]{64}" maxLength={64} required disabled={busy} autoComplete="off" autoCapitalize="off" spellCheck={false} placeholder="Одноразовый билет" /></label>
      <p className="field-hint">Билет выдаётся командой issue-ticket.sh --invite. Обычный билет на очередь не подходит. Собеседнику билет не нужен.</p>
    </div>}
    <div className="form-note"><Icon name="lock" size={17} /><span>Приглашение открывает личный разговор. Личность собеседника можно проверить отдельно, сравнив код при встрече или по доверенному каналу.</span></div>
    <button className="button primary full" type="submit" disabled={busy || scanning}>{busy ? "Минуточку, кот работает…" : kind === "create" ? "Создать ссылку и QR-код" : "Принять приглашение"}<Icon name="arrow" size={18} /></button>
    <button className="button text-button legacy-invite" type="button" disabled={busy} onClick={legacy}>Старый формат приглашения</button>
  </form>;
}

export function QuickInvitationExport({ data }: { data: QuickInvitationData }) {
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState(false);
  const [shareError, setShareError] = useState(false);
  const [enlarged, setEnlarged] = useState(false);
  const enlargeButton = useRef<HTMLButtonElement>(null);
  const previouslyEnlarged = useRef(false);
  const qr = useMemo(() => { try { return invitationQr(data.link); } catch { return null; } }, [data.link]);
  const safeLink = useMemo(() => { try { return normalizeInvitationLink(data.link); } catch { return null; } }, [data.link]);
  const { frame, width } = useQrDisplaySize(qr?.size ?? 0, enlarged);
  useEffect(() => {
    if (previouslyEnlarged.current && !enlarged) enlargeButton.current?.focus();
    previouslyEnlarged.current = enlarged;
  }, [enlarged]);
  async function copy() {
    if (!safeLink) return;
    try { await navigator.clipboard.writeText(safeLink); setCopied(true); setCopyError(false); }
    catch { setCopyError(true); }
  }
  async function share() {
    if (!safeLink || typeof navigator.share !== "function") return;
    try { await navigator.share({ title: "Приглашение в КотоПизделку", text: safeLink }); setShareError(false); }
    catch (reason) { if (!(reason instanceof DOMException && reason.name === "AbortError")) setShareError(true); }
  }
  const expires = new Date(data.expires_at * 1000);
  const image = qr && <div className="invitation-qr-frame" ref={frame}>{width > 0 ? <svg role="img" aria-label="QR-код приглашения" viewBox={`0 0 ${qr.size} ${qr.size}`} width={width} height={width} style={{ width, height: width }} shapeRendering="crispEdges"><rect width={qr.size} height={qr.size} fill="white" /><path d={qr.path} fill="black" /></svg> : <p className="field-hint qr-size-note">{enlarged ? "Для QR-кода мало места. Вернитесь к ссылке и скопируйте её." : "Для QR-кода сейчас мало места. Увеличьте его или скопируйте ссылку."}</p>}</div>;
  if (enlarged && qr) return <div className="modal-body qr-expanded">
    <button className="button secondary qr-back" type="button" autoFocus onClick={() => setEnlarged(false)}><Icon name="arrow" size={17} />Вернуться к ссылке</button>
    {image}
  </div>;
  return <div className="modal-body">
    <p className="form-intro">Покажите QR-код при встрече или передайте одну ссылку выбранному собеседнику. Его ответ появится здесь автоматически.</p>
    {qr ? <figure className="invitation-qr">{image}<figcaption>Один QR-код — одно знакомство</figcaption><button className="button secondary qr-enlarge" ref={enlargeButton} type="button" onClick={() => setEnlarged(true)}>Увеличить QR-код</button></figure> : <p className="field-hint">QR-код недоступен. Используйте ссылку ниже.</p>}
    <label>Ссылка для собеседника<textarea className="artifact-input export-text" value={data.link} readOnly rows={3} spellCheck={false} aria-label="Ссылка для собеседника" /></label>
    <button className="button primary full" type="button" disabled={!safeLink} onClick={() => void copy()}><Icon name={copied ? "check" : "copy"} size={17} />{copied ? "Ссылка скопирована" : "Скопировать ссылку"}</button>
    {safeLink && typeof navigator.share === "function" && <button className="button secondary full share-invitation" type="button" onClick={() => void share()}>Передать ссылку<Icon name="arrow" size={17} /></button>}
    {copyError && <p className="inline-error" role="alert">Буфер обмена недоступен. Выделите ссылку и скопируйте вручную.</p>}
    {shareError && <p className="inline-error" role="alert">Не получилось открыть меню отправки. Скопируйте ссылку кнопкой выше.</p>}
    <p className="field-hint invitation-expiry">{Number.isFinite(expires.getTime()) ? `Приглашение действует до ${expires.toLocaleString("ru-RU")}.` : "Приглашение действует ограниченное время."}</p>
    <div className="form-note"><Icon name="mail" size={17} /><span>Ссылка даёт право ответить на приглашение. Не публикуйте её для случайных котов.</span></div>
  </div>;
}

function useQrDisplaySize(size: number, enlarged: boolean) {
  const frame = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(0);
  useEffect(() => {
    const element = frame.current;
    if (!element || !size) return;
    const dialog = element.closest("dialog");
    const measure = () => {
      const viewportHeight = window.visualViewport?.height ?? window.innerHeight;
      // Reserve the real header and intro height so the initial code is not clipped.
      // Adding scrollTop keeps the measurement stable when text is scrolled away.
      const prefix = dialog ? element.getBoundingClientRect().top - dialog.getBoundingClientRect().top + dialog.scrollTop : 0;
      const height = enlarged ? viewportHeight - 110 : dialog ? Math.min(viewportHeight - 20, dialog.clientHeight) - prefix - 4 : viewportHeight - 240;
      const next = invitationQrDisplaySize(size, element.getBoundingClientRect().width, height, window.devicePixelRatio || 1, enlarged);
      setWidth(previous => Math.abs(previous - next) < 1e-6 ? previous : next);
    };
    const observer = new ResizeObserver(measure);
    observer.observe(element);
    if (dialog) observer.observe(dialog);
    const intro = dialog?.querySelector(".form-intro");
    if (intro) observer.observe(intro);
    window.addEventListener("resize", measure);
    window.visualViewport?.addEventListener("resize", measure);
    let ratioQuery: MediaQueryList;
    const watchRatio = () => {
      ratioQuery?.removeEventListener("change", ratioChanged);
      ratioQuery = window.matchMedia(`(resolution: ${window.devicePixelRatio || 1}dppx)`);
      ratioQuery.addEventListener("change", ratioChanged);
    };
    function ratioChanged() { measure(); watchRatio(); }
    watchRatio();
    measure();
    return () => {
      observer.disconnect();
      window.removeEventListener("resize", measure);
      window.visualViewport?.removeEventListener("resize", measure);
      ratioQuery.removeEventListener("change", ratioChanged);
    };
  }, [size, enlarged]);
  return { frame, width };
}

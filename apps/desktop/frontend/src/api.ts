import { invoke, isTauri } from "@tauri-apps/api/core";

export const inNative = isTauri();

export type ContactStage = "archived" | "queue_pending" | "offer_pending" | "waiting_first_message" | "ready" | "legacy" | "quick_queue_pending" | "quick_pending" | "quick_confirmation" | "quick_waiting" | "quick_expired";
export interface BackgroundSettings { supported: boolean; enabled: boolean; interval_minutes: number }
export interface NotificationSettings { supported: boolean; enabled: boolean; allowed: boolean }
export interface ProfileStatus {
  open: boolean;
  nickname: string;
}
export interface ContactView {
  id: string;
  stage: ContactStage;
  can_send: boolean;
  verified?: boolean | null;
  quick?: boolean;
  unread: number;
  nickname: string;
  alias: string;
}
export interface InvitationExport {
  contact: string;
  invitation: string;
  fingerprint: string;
}
export interface QuickInvitationExport {
  contact: string;
  link: string;
  expires_at: number;
}
export interface VerificationView {
  fingerprint: string;
  verified: boolean;
}
export interface HistoryEntry {
  sequence: number;
  direction: "incoming" | "outgoing";
  text: string;
  id: string;
  unread: boolean;
  delivery: "queued" | "server" | "delivered" | null;
}
export interface SyncReport {
  sent: number;
  received: number;
  duplicates: number;
  acked: number;
  profile_changed: boolean;
  delivery_changed: boolean;
}

export interface AccountView { login: string | null; authenticated: boolean; registered: boolean; requests: AccountRequest[] }
export interface AccountRequest { id: string; login: string; incoming: boolean; status: string; contact: string | null }
type Request =
  | { kind: "account_status" | "sync_account" | "logout_account" | "create_account_link" }
  | { kind: "authenticate_account"; login: string; password: string; register: boolean }
  | { kind: "find_account" | "add_account"; login: string }
  | { kind: "decide_account"; id: string; accept: boolean }
  | { kind: "status" | "open_profile" | "contacts" }
  | { kind: "set_nickname"; nickname: string }
  | { kind: "set_contact_alias"; contact: string; alias: string }
  | { kind: "mark_read"; contact: string; sequences: number[] }
  | { kind: "history"; contact: string; after_sequence: number }
  | { kind: "enqueue"; contact: string; text: string }
  | { kind: "sync" | "export_invitation"; contact: string }
  | { kind: "create_invitation"; relay_url: string; ticket: string }
  | { kind: "accept_invitation"; offer: string; trusted_fingerprint: string; relay_url: string; ticket: string }
  | { kind: "complete_invitation"; contact: string; reply: string; trusted_fingerprint: string }
  | { kind: "provision_queue"; contact: string; ticket: string | null }
  | { kind: "delete_contact"; contact: string }
  | { kind: "provision_quick"; contact: string; ticket: string | null }
  | { kind: "create_quick"; relay_url: string; ticket: string }
  | { kind: "accept_quick"; link: string }
  | { kind: "export_quick" | "confirm_quick" | "verification"; contact: string }
  | { kind: "mark_verified"; contact: string; fingerprint: string };
type Reply =
  | { kind: "account"; view: AccountView }
  | { kind: "account_user"; login: string }
  | ({ kind: "profile" } & ProfileStatus)
  | { kind: "contacts"; contacts: ContactView[] }
  | { kind: "history"; entries: HistoryEntry[] }
  | { kind: "queued"; id: string }
  | ({ kind: "synced" } & SyncReport)
  | ({ kind: "invitation" } & InvitationExport)
  | ({ kind: "quick_invitation" } & QuickInvitationExport)
  | ({ kind: "verification" } & VerificationView)
  | { kind: "done" };

async function dispatch<K extends Reply["kind"]>(request: Request, expected: K): Promise<Extract<Reply, { kind: K }>> {
  const reply = await invoke<Reply>("dispatch", { request });
  if (reply.kind !== expected) throw "Приложение получило неожиданный ответ. Закройте и откройте его снова.";
  return reply as Extract<Reply, { kind: K }>;
}

/** All networking, profile paths and key handling remain in Rust. */
export const api = {
  account: async () => (await dispatch({kind:"account_status"}, "account")).view,
  syncAccount: async () => (await dispatch({kind:"sync_account"}, "account")).view,
  authenticateAccount: async (login:string,password:string,register:boolean) => (await dispatch({kind:"authenticate_account",login,password,register}, "account")).view,
  logoutAccount: async () => (await dispatch({kind:"logout_account"}, "account")).view,
  findAccount: (login:string) => dispatch({kind:"find_account",login}, "account_user"),
  addAccount: async (login:string) => (await dispatch({kind:"add_account",login}, "account")).view,
  decideAccount: async (id:string,accept:boolean) => (await dispatch({kind:"decide_account",id,accept}, "account")).view,
  status: () => dispatch({ kind: "status" }, "profile"),
  open: () => dispatch({ kind: "open_profile" }, "profile"),
  setNickname: (nickname: string) => dispatch({ kind: "set_nickname", nickname }, "profile"),
  setContactAlias: (contact: string, alias: string) => dispatch({ kind: "set_contact_alias", contact, alias }, "done"),
  contacts: async () => (await dispatch({ kind: "contacts" }, "contacts")).contacts,
  createOffer: (relayUrl: string, provisionTicket: string) =>
    dispatch({ kind: "create_invitation", relay_url: relayUrl, ticket: provisionTicket }, "invitation"),
  acceptOffer: (invitation: string, trustedFingerprint: string, relayUrl: string, provisionTicket: string) =>
    dispatch({ kind: "accept_invitation", offer: invitation, trusted_fingerprint: trustedFingerprint, relay_url: relayUrl, ticket: provisionTicket }, "invitation"),
  completeOffer: (contactId: string, invitation: string, trustedFingerprint: string) =>
    dispatch({ kind: "complete_invitation", contact: contactId, reply: invitation, trusted_fingerprint: trustedFingerprint }, "done"),
  exportInvitation: (contactId: string) => dispatch({ kind: "export_invitation", contact: contactId }, "invitation"),
  history: async (contactId: string, afterSequence: number) =>
    (await dispatch({ kind: "history", contact: contactId, after_sequence: afterSequence }, "history")).entries,
  enqueue: (contactId: string, text: string) => dispatch({ kind: "enqueue", contact: contactId, text }, "queued"),
  sync: (contactId: string) => dispatch({ kind: "sync", contact: contactId }, "synced"),
  provision: (contact: string, ticket: string | null) => dispatch({ kind: "provision_queue", contact, ticket }, "invitation"),
  markRead: (contact: string, sequences: number[]) => dispatch({ kind: "mark_read", contact, sequences }, "done"),
  deleteContact: (contact: string) => dispatch({ kind: "delete_contact", contact }, "done"),
  provisionQuick: (contact: string, ticket: string | null) => dispatch({ kind: "provision_quick", contact, ticket }, "quick_invitation"),
  createAccountLink: () => dispatch({ kind: "create_account_link" }, "quick_invitation"),
  createQuick: (relayUrl: string, ticket: string) => dispatch({ kind: "create_quick", relay_url: relayUrl, ticket }, "quick_invitation"),
  acceptQuick: (link: string) => dispatch({ kind: "accept_quick", link }, "quick_invitation"),
  exportQuick: (contact: string) => dispatch({ kind: "export_quick", contact }, "quick_invitation"),
  confirmQuick: (contact: string) => dispatch({ kind: "confirm_quick", contact }, "done"),
  verification: (contact: string) => dispatch({ kind: "verification", contact }, "verification"),
  markVerified: (contact: string, fingerprint: string) => dispatch({ kind: "mark_verified", contact, fingerprint }, "done"),
  takePendingInvitation: () => invoke<string | null>("take_pending_invitation"),
  backgroundSettings: () => invoke<BackgroundSettings>("background_settings"),
  setBackground: (enabled: boolean) => invoke<BackgroundSettings>("set_background", { enabled }),
  notificationSettings: () => invoke<NotificationSettings>("notification_settings"),
  setNotifications: (enabled: boolean) => invoke<NotificationSettings>("set_notifications", { enabled }),
  notificationView: (contact: string | null) => invoke<void>("notification_view", { contact }),
  scanInvitation: () => invoke<string | null>("scan_invitation"),
};

export async function profileBackup(mode: "export" | "verify" | "restore", password: string): Promise<boolean> {
  return invoke<boolean>("profile_backup", { password, restore: mode === "restore", verify: mode === "verify" });
}

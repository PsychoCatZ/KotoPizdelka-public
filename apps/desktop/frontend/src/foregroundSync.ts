import type { ContactStage, SyncReport } from "./api";

export interface SyncTarget { id: string; stage: ContactStage }
interface RetryState { next: number; failures: number }
export interface SyncClock {
  now: () => number;
  setTimeout: (callback: () => void, delay: number) => unknown;
  clearTimeout: (timer: unknown) => void;
}
interface Options {
  contacts: () => readonly SyncTarget[];
  canRun: () => boolean;
  sync: (id: string) => Promise<SyncReport>;
  onResult: (id: string, report: SyncReport, canContinue: () => boolean) => Promise<void>;
  onError?: (id: string, canContinue: () => boolean) => Promise<void>;
  onActivity?: (id: string | null) => void;
  clock?: SyncClock;
}

const PERIOD = 10_000;
const MAX_BACKOFF = 120_000;
export const canSyncStage = (stage: ContactStage) => stage === "ready" || stage === "legacy" || stage === "waiting_first_message" || stage === "quick_queue_pending" || stage === "quick_pending" || stage === "quick_waiting";

/** Manual sync joins an existing request for its contact, even while automatic mode pauses. */
export function singleFlightSync(sync: (id: string) => Promise<SyncReport>) {
  const flights = new Map<string, Promise<SyncReport>>();
  return {
    get active() { return flights.size; },
    sync(id: string) {
      const existing = flights.get(id);
      if (existing) return existing;
      const promise = sync(id).finally(() => { if (flights.get(id) === promise) flights.delete(id); });
      flights.set(id, promise);
      return promise;
    },
  };
}

/** A single foreground worker. A trigger never launches a parallel native call. */
export class ForegroundSyncScheduler {
  private enabled = false;
  private disposed = false;
  private running = false;
  private timer: unknown = null;
  private retries = new Map<string, RetryState>();
  private pending = new Set<string>();
  private urgent = new Set<string>();
  private cursor: string | null = null;
  private clock: SyncClock;

  constructor(private options: Options) {
    this.clock = options.clock ?? {
      now: () => Date.now(),
      setTimeout: (callback, delay) => globalThis.setTimeout(callback, delay),
      clearTimeout: timer => globalThis.clearTimeout(timer as ReturnType<typeof setTimeout>),
    };
  }

  setEnabled(enabled: boolean) {
    if (this.disposed || enabled === this.enabled) return;
    this.enabled = enabled;
    this.cancelTimer();
    if (enabled) this.trigger();
  }

  /** New durable outgoing data and foreground/online events deserve one fresh attempt. */
  trigger(id?: string) {
    if (this.disposed) return;
    for (const contact of this.options.contacts()) {
      if (canSyncStage(contact.stage) && (!id || contact.id === id)) { this.pending.add(contact.id); if (id) this.urgent.add(contact.id); }
    }
    this.wake();
  }

  /** Reconsider contacts after a user action, without bypassing ordinary retry deadlines. */
  wake() {
    if (this.disposed || !this.enabled || this.running) return;
    this.cancelTimer();
    this.schedule();
  }

  dispose() {
    this.disposed = true;
    this.enabled = false;
    this.cancelTimer();
    this.pending.clear();
    this.urgent.clear();
  }

  private cancelTimer() {
    if (this.timer !== null) this.clock.clearTimeout(this.timer);
    this.timer = null;
  }

  private schedule() {
    if (this.disposed || !this.enabled || this.running) return;
    const contacts = this.options.contacts().filter(contact => canSyncStage(contact.stage));
    const ids = new Set(contacts.map(contact => contact.id));
    for (const id of this.retries.keys()) if (!ids.has(id)) this.retries.delete(id);
    for (const id of this.pending) if (!ids.has(id)) this.pending.delete(id);
    for (const id of this.urgent) if (!ids.has(id)) this.urgent.delete(id);
    let delay = PERIOD;
    if (!this.options.canRun()) delay = 1_000;
    else for (const contact of contacts) {
      const next = this.pending.has(contact.id) ? 0 : this.retries.get(contact.id)?.next ?? 0;
      delay = Math.min(delay, Math.max(0, next - this.clock.now()));
    }
    this.timer = this.clock.setTimeout(() => { this.timer = null; void this.pump(); }, delay);
  }

  private async pump() {
    if (this.disposed || !this.enabled || this.running) return;
    this.running = true;
    const canContinue = () => !this.disposed && this.enabled && this.options.canRun();
    try {
      if (!canContinue()) return;
      const contacts = this.options.contacts().filter(contact => canSyncStage(contact.stage));
      const cursor = contacts.findIndex(contact => contact.id === this.cursor);
      const rotated = [...contacts.slice(cursor + 1), ...contacts.slice(0, cursor + 1)];
      const candidates = rotated.filter(contact => this.pending.has(contact.id) || (this.retries.get(contact.id)?.next ?? 0) <= this.clock.now());
      candidates.sort((a, b) => Number(this.urgent.has(b.id)) - Number(this.urgent.has(a.id)) || Number(this.pending.has(b.id)) - Number(this.pending.has(a.id)));
      const contact = candidates[0];
      if (contact) {
        this.cursor = contact.id;
        const previous = this.retries.get(contact.id) ?? { next: 0, failures: 0 };
        this.pending.delete(contact.id);
        this.urgent.delete(contact.id);
        this.options.onActivity?.(contact.id);
        try {
          const report = await this.options.sync(contact.id);
          if (this.disposed) return;
          await this.options.onResult(contact.id, report, canContinue);
          this.retries.set(contact.id, { next: this.clock.now() + PERIOD, failures: 0 });
        } catch {
          if (this.disposed) return;
          const failures = previous.failures + 1;
          this.retries.set(contact.id, { next: this.clock.now() + Math.min(MAX_BACKOFF, PERIOD * 2 ** Math.min(failures - 1, 5)), failures });
          try { await this.options.onError?.(contact.id, canContinue); }
          catch { /* A failed UI refresh must not terminate the worker. */ }
        } finally {
          if (!this.disposed) this.options.onActivity?.(null);
        }
      }
    } finally {
      this.running = false;
      this.schedule();
    }
  }
}

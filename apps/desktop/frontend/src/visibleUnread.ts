/** Local-only read tracking. Never uses an entire-chat cursor. */
export type MessageRect = { top: number; bottom: number; left: number; right: number; height: number; width: number };
export function hasVisibleMessage(message: MessageRect, viewport: MessageRect): boolean {
  const height = Math.min(message.bottom, viewport.bottom) - Math.max(message.top, viewport.top);
  const width = Math.min(message.right, viewport.right) - Math.max(message.left, viewport.left);
  return message.height > 0 && message.width > 0 && height >= Math.min(24, message.height) && width >= Math.min(16, message.width);
}
export class VisibleReadBatcher {
  private pending = new Map<string, Set<number>>();
  private running = false;
  private disposed = false;
  constructor(private options: {
    canMark: (contact: string, sequence: number) => boolean;
    mark: (contact: string, sequences: number[]) => Promise<unknown>;
    committed: (contact: string, sequences: number[]) => Promise<void> | void;
    failed: (error: unknown) => void;
  }) {}
  offer(contact: string, sequences: number[]) {
    if (this.disposed) return;
    let pending = this.pending.get(contact);
    if (!pending) { pending = new Set(); this.pending.set(contact, pending); }
    for (const sequence of sequences) if (Number.isSafeInteger(sequence) && sequence > 0) pending.add(sequence);
    queueMicrotask(() => { void this.flush(); });
  }
  async flush() {
    if (this.disposed || this.running) return;
    this.running = true;
    try {
      while (!this.disposed && this.pending.size) {
        const [contact, pending] = this.pending.entries().next().value!;
        // Selection, focus or a modal may have changed since observation.
        const sequences = [...pending].filter(sequence => this.options.canMark(contact, sequence)).slice(0, 100);
        if (!sequences.length) { this.pending.delete(contact); continue; }
        for (const sequence of sequences) pending.delete(sequence);
        if (!pending.size) this.pending.delete(contact);
        try { await this.options.mark(contact, sequences); }
        catch (error) {
          if (!this.disposed) this.options.failed(error);
          // UI flags stay unread; a later view/scroll/focus event can retry.
          this.pending.clear(); return;
        }
        if (!this.disposed) await this.options.committed(contact, sequences);
      }
    } catch (error) { if (!this.disposed) this.options.failed(error); }
    finally { this.running = false; }
  }
  dispose() { this.disposed = true; this.pending.clear(); }
}

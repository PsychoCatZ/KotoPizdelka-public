import type { HistoryEntry } from "./api";

export function mergeHistory(existing: readonly HistoryEntry[], next: readonly HistoryEntry[]) {
  const merged = new Map(existing.map(entry => [entry.sequence, entry]));
  for (const entry of next) merged.set(entry.sequence, entry);
  return [...merged.values()].sort((a, b) => a.sequence - b.sequence);
}

/** The native API walks oldest-first pages; retain loaded pages while reaching new entries. */
export async function appendHistoryTail(options: {
  read: (after: number) => Promise<HistoryEntry[]>;
  current: () => readonly HistoryEntry[];
  canContinue: () => boolean;
  append: (entries: HistoryEntry[]) => void;
  setHasMore: (more: boolean) => void;
  maxPages?: number;
}) {
  const pending = options.current().filter(entry => entry.direction === "outgoing" && entry.delivery !== "delivered");
  const pages = new Set(pending.map(entry => {
    const index = options.current().findIndex(item => item.sequence === entry.sequence);
    return Math.floor(index / 100);
  }));
  const initial = options.current();
  for (const page of pages) {
    if (!options.canContinue()) return false;
    const after = page === 0 ? 0 : initial[page * 100 - 1]?.sequence ?? 0;
    const entries = await options.read(after);
    if (!options.canContinue()) return false;
    options.append(mergeHistory(options.current(), entries));
  }
  for (let page = 0; page < (options.maxPages ?? 5); page++) {
    if (!options.canContinue()) return false;
    const current = options.current();
    const after = current[current.length - 1]?.sequence ?? 0;
    const entries = await options.read(after);
    if (!options.canContinue()) return false;
    if (entries.length) options.append(mergeHistory(options.current(), entries));
    options.setHasMore(entries.length === 100);
    if (entries.length < 100) return true;
    // A malformed page cannot make this worker loop forever.
    if (entries[entries.length - 1].sequence <= after) return false;
  }
  return false;
}

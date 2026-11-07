import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { transform } from "esbuild";

async function source(name) {
  const compiled = await transform(await readFile(new URL(`../src/${name}.ts`, import.meta.url), "utf8"), { loader: "ts", format: "esm", target: "es2022" });
  return import(`data:text/javascript;base64,${Buffer.from(compiled.code).toString("base64")}`);
}
const { ForegroundSyncScheduler, singleFlightSync } = await source("foregroundSync");
const { appendHistoryTail, mergeHistory } = await source("historyTail");
const report = { sent: 0, received: 0, acked: 0, duplicates: 0 };
const target = (id, stage = "ready") => ({ id, stage });
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const settle = async () => { for (let i = 0; i < 20; i++) await Promise.resolve(); };

class Clock {
  time = 0; nextId = 0; jobs = new Map();
  now = () => this.time;
  setTimeout = (callback, delay) => { const id = ++this.nextId; this.jobs.set(id, { callback, at: this.time + delay }); return id; };
  clearTimeout = id => { this.jobs.delete(id); };
  async advance(milliseconds) {
    const until = this.time + milliseconds;
    for (let guard = 0; guard < 1000; guard++) {
      await settle();
      const due = [...this.jobs].filter(([, job]) => job.at <= until).sort((a, b) => a[1].at - b[1].at)[0];
      if (!due) { this.time = until; await settle(); return; }
      this.time = due[1].at; this.jobs.delete(due[0]); due[1].callback();
    }
    throw new Error("Timer did not settle");
  }
}
const worker = (clock, options) => new ForegroundSyncScheduler({ contacts: () => [target("a")], canRun: () => true, sync: async () => report, onResult: async () => {}, clock, ...options });

test("eligible contacts run sequentially and many triggers coalesce into one subsequent pass", async () => {
  const clock = new Clock(), first = deferred(), calls = [];
  let active = 0, maximum = 0;
  const scheduler = worker(clock, {
    contacts: () => [target("a"), target("b", "waiting_first_message"), target("c", "legacy"), target("offer", "offer_pending"), target("queue", "queue_pending")],
    sync: async id => { calls.push(id); maximum = Math.max(maximum, ++active); if (calls.length === 1) await first.promise; active--; return report; },
  });
  scheduler.setEnabled(true); await clock.advance(0);
  assert.deepEqual(calls, ["a"]);
  scheduler.trigger("a"); scheduler.trigger("a"); scheduler.trigger("a");
  await clock.advance(1000); assert.deepEqual(calls, ["a"]);
  first.resolve(); await clock.advance(0);
  assert.deepEqual(calls, ["a", "a", "b", "c"]); assert.equal(maximum, 1);
  scheduler.dispose();
});

test("quick handshakes poll automatically while candidate approval and expired invitations stay paused", async () => {
  const clock = new Clock(), calls = [];
  const scheduler = worker(clock, {
    contacts: () => [target("setup", "quick_queue_pending"), target("issuer", "quick_pending"), target("recipient", "quick_waiting"), target("approval", "quick_confirmation"), target("expired", "quick_expired")],
    sync: async id => { calls.push(id); return report; },
  });
  scheduler.setEnabled(true); await clock.advance(0);
  assert.deepEqual(calls, ["setup", "issuer", "recipient"]);
  scheduler.dispose();
});

test("per-contact exponential backoff caps at 120s and online recovery does not delay healthy contacts", async () => {
  const clock = new Clock(), times = [], healthy = [];
  let failed = true;
  const scheduler = worker(clock, {
    contacts: () => [target("a"), target("b")],
    sync: async id => { if (id === "b") { healthy.push(clock.time); return report; } times.push(clock.time); if (failed) throw "offline"; return report; },
  });
  scheduler.setEnabled(true); await clock.advance(390000);
  assert.deepEqual(times, [0, 10000, 30000, 70000, 150000, 270000, 390000]);
  assert.equal(healthy.length, 40);
  failed = false; scheduler.trigger(); await clock.advance(0); assert.equal(times.at(-1), 390000);
  await clock.advance(10000); assert.equal(times.at(-1), 400000);
  scheduler.dispose();
});

test("hidden pauses following calls, foreground resumes, and disposal suppresses stale callbacks", async () => {
  const clock = new Clock(), first = deferred(), calls = [], results = [];
  const scheduler = worker(clock, {
    contacts: () => [target("a"), target("b")],
    sync: async id => { calls.push(id); if (calls.length === 1) await first.promise; return report; },
    onResult: async (id, _, canContinue) => { results.push([id, canContinue()]); },
  });
  scheduler.setEnabled(true); await clock.advance(0); scheduler.setEnabled(false);
  first.resolve(); await clock.advance(120000);
  assert.deepEqual(calls, ["a"]); assert.deepEqual(results, [["a", false]]);
  scheduler.setEnabled(true); await clock.advance(0); assert.deepEqual(calls, ["a", "b", "a"]);
  scheduler.dispose(); await clock.advance(120000); assert.equal(calls.length, 3);
  const last = deferred(); let callbacks = 0;
  const disposed = worker(clock, { sync: () => last.promise, onResult: async () => { callbacks++; } });
  disposed.setEnabled(true); await clock.advance(0); disposed.dispose(); last.resolve(report); await clock.advance(120000);
  assert.equal(callbacks, 0);
});

test("durable enqueue trigger is deferred during manual work then attempts immediately", async () => {
  const clock = new Clock(), calls = [];
  let manual = false;
  const scheduler = worker(clock, { canRun: () => !manual, sync: async id => { calls.push([id, clock.time]); return report; } });
  scheduler.setEnabled(true); await clock.advance(0);
  await clock.advance(1000); manual = true; scheduler.trigger("a"); await clock.advance(0);
  assert.equal(calls.length, 1);
  manual = false; scheduler.wake(); await clock.advance(0);
  assert.deepEqual(calls, [["a", 0], ["a", 1000]]);
  scheduler.dispose();
});

test("new outgoing target gets the next slot ahead of ordinary due contacts", async () => {
  const clock = new Clock(), pending = deferred(), calls = [];
  const scheduler = worker(clock, {
    contacts: () => [target("a"), target("b"), target("c")],
    sync: async id => { calls.push(id); if (calls.length === 1) await pending.promise; return report; },
  });
  scheduler.setEnabled(true); await clock.advance(0); scheduler.trigger("c");
  pending.resolve(); await clock.advance(0);
  assert.deepEqual(calls, ["a", "c", "b"]);
  scheduler.dispose();
});

test("manual request joins the in-flight automatic request and survives scheduler effect disposal", async () => {
  const pending = deferred(); let calls = 0;
  const shared = singleFlightSync(() => { calls++; return pending.promise; });
  const automatic = shared.sync("a"), manual = shared.sync("a");
  assert.equal(automatic, manual); assert.equal(calls, 1); assert.equal(shared.active, 1);
  pending.resolve(report); assert.deepEqual(await manual, report); assert.equal(shared.active, 0);
  assert.notEqual(shared.sync("a"), automatic); assert.equal(calls, 2); await settle();
});

const entry = sequence => ({ sequence, direction: "incoming", text: `message-${sequence}`, id: `id-${sequence}` });
test("history refresh reaches incoming entries after 100+ old entries without replacing loaded pages", async () => {
  let history = Array.from({ length: 200 }, (_, i) => entry(i + 1)), more = true;
  const original = history[0]; const requests = [];
  const tail = Array.from({ length: 401 }, (_, i) => entry(i + 201));
  const complete = await appendHistoryTail({
    read: async after => { requests.push(after); return tail.filter(item => item.sequence > after).slice(0, 100); },
    current: () => history, canContinue: () => true,
    append: next => { history = next; }, setHasMore: next => { more = next; },
  });
  assert.equal(complete, true); assert.equal(history.length, 601); assert.equal(history[0], original); assert.equal(history.at(-1).sequence, 601);
  assert.deepEqual(requests, [200, 300, 400, 500, 600]); assert.equal(more, false);
  assert.deepEqual(mergeHistory(history, [entry(601)]), history);
});

test("history refresh yields after five pages and continues a dirty tail later", async () => {
  let history = [entry(1)], more = true, calls = 0;
  const options = {
    read: async after => { calls++; return Array.from({ length: Math.min(100, 650 - after) }, (_, i) => entry(after + i + 1)); },
    current: () => history, canContinue: () => true,
    append: next => { history = next; }, setHasMore: next => { more = next; },
  };
  assert.equal(await appendHistoryTail(options), false); assert.equal(calls, 5); assert.equal(history.length, 501); assert.equal(more, true);
  assert.equal(await appendHistoryTail(options), true); assert.equal(calls, 7); assert.equal(history.length, 650); assert.equal(more, false);
});

test("a selected-contact change or hidden state rejects a stale history response", async () => {
  const pending = deferred(); let selected = "a", visible = true, history = [entry(1)], more = true, calls = 0;
  const refreshing = appendHistoryTail({
    read: () => { calls++; return pending.promise; }, current: () => history,
    canContinue: () => selected === "a" && visible,
    append: next => { history = next; }, setHasMore: next => { more = next; },
  });
  selected = "b"; visible = false; pending.resolve([entry(2)]);
  assert.equal(await refreshing, false); assert.deepEqual(history, [entry(1)]); assert.equal(more, true); assert.equal(calls, 1);
});

test("sync partial commit followed by rejection still exposes the durable inbox once", async () => {
  const clock = new Clock(); let stored = [entry(1)], displayed = [], failureReads = 0;
  const scheduler = worker(clock, {
    sync: async () => { stored.push(entry(2)); throw "ACK failed after commit"; },
    onError: async (_, canContinue) => {
      await appendHistoryTail({ read: async after => { failureReads++; return stored.filter(item => item.sequence > after); }, current: () => displayed, canContinue,
        append: next => { displayed = next; }, setHasMore: () => {} });
    },
  });
  scheduler.setEnabled(true); await clock.advance(0);
  assert.deepEqual(displayed, stored); assert.equal(failureReads, 1);
  scheduler.dispose();
});

test("delivery refresh updates already loaded outgoing rows without dropping history", async () => {
  let history = [{ ...entry(1), direction: "outgoing", delivery: "server" }, entry(2)];
  const delivered = { ...history[0], delivery: "delivered" };
  const requests = [];
  await appendHistoryTail({
    read: async after => { requests.push(after); return [delivered, entry(2)].filter(item => item.sequence > after); },
    current: () => history, canContinue: () => true,
    append: next => { history = next; }, setHasMore: () => {},
  });
  assert.equal(history[0].delivery, "delivered"); assert.equal(history.length, 2); assert.deepEqual(requests, [0,2]);
});

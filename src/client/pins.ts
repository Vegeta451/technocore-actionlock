import type { ScanEvent } from "@/server/types";

const DATABASE = "actionlock-local-evidence";
const STORE = "pins";
const MAX_PINS = 100;

export interface PinnedEvidence {
  id: string;
  room: string;
  pinnedAt: string;
  event: ScanEvent;
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE)) {
        request.result.createObjectStore(STORE, { keyPath: "id" });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Local evidence database failed to open"));
  });
}

function complete(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error ?? new Error("Local evidence transaction failed"));
    transaction.onabort = () => reject(transaction.error ?? new Error("Local evidence transaction was aborted"));
  });
}

export async function listPins(): Promise<PinnedEvidence[]> {
  const database = await openDatabase();
  try {
    const transaction = database.transaction(STORE, "readonly");
    const request = transaction.objectStore(STORE).getAll();
    const records = await new Promise<PinnedEvidence[]>((resolve, reject) => {
      request.onsuccess = () => resolve(request.result as PinnedEvidence[]);
      request.onerror = () => reject(request.error ?? new Error("Local evidence could not be read"));
    });
    return records.sort((left, right) => right.pinnedAt.localeCompare(left.pinnedAt));
  } finally {
    database.close();
  }
}

export async function pinEvidence(room: string, event: ScanEvent): Promise<PinnedEvidence[]> {
  const database = await openDatabase();
  try {
    const transaction = database.transaction(STORE, "readwrite");
    const store = transaction.objectStore(STORE);
    const id = `${room}:${event.message.seq}:${event.provenance.contentHash}`;
    store.put({ id, room, event, pinnedAt: new Date().toISOString() } satisfies PinnedEvidence);
    const request = store.getAll();
    const records = await new Promise<PinnedEvidence[]>((resolve, reject) => {
      request.onsuccess = () => resolve(request.result as PinnedEvidence[]);
      request.onerror = () => reject(request.error ?? new Error("Local evidence could not be read"));
    });
    records.sort((left, right) => right.pinnedAt.localeCompare(left.pinnedAt));
    for (const stale of records.slice(MAX_PINS)) store.delete(stale.id);
    await complete(transaction);
  } finally {
    database.close();
  }
  return listPins();
}

export async function removePin(id: string): Promise<PinnedEvidence[]> {
  const database = await openDatabase();
  try {
    const transaction = database.transaction(STORE, "readwrite");
    transaction.objectStore(STORE).delete(id);
    await complete(transaction);
  } finally {
    database.close();
  }
  return listPins();
}

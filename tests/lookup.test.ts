import { afterEach, describe, expect, it, vi } from "vitest";
import { lookupRoomSequence } from "../src/server/scan";

afterEach(() => vi.restoreAllMocks());

function exportResponse(sequences: number[]): Response {
  const body = sequences.map((seq) => JSON.stringify({
    seq,
    ts: "2026-08-31T00:00:00Z",
    from: "tester",
    text: `message ${seq}`,
  })).join("\n");
  return new Response(body, { status: 200 });
}

describe("exact sequence lookup", () => {
  it("returns a normal scan event for retained evidence", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(exportResponse([41, 42, 43]));
    const result = await lookupRoomSequence({ room: "lobby", sequence: "42" });
    expect(result.status).toBe("found");
    expect(result.event?.message.seq).toBe("42");
    expect(result.event?.provenance.room).toBe("lobby");
  });

  it("distinguishes an expired sequence from an unexplained gap", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(exportResponse([50, 51]));
    expect((await lookupRoomSequence({ room: "lobby", sequence: "42" })).status).toBe("not_retained");

    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(exportResponse([40, 42]));
    expect((await lookupRoomSequence({ room: "lobby", sequence: "41" })).status).toBe("not_found");
  });
});

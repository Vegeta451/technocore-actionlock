import { afterEach, describe, expect, it, vi } from "vitest";
import { TechnocoreClient } from "../src/server/client";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("Technocore read resilience", () => {
  it("retries bounded transient upstream failures", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response("Service Unavailable", { status: 503 }))
      .mockResolvedValueOnce(new Response("Bad Gateway", { status: 502 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        room: "lobby",
        count: 1,
        first_seq: 42,
        last_seq: 42,
        messages: [{ seq: 42, ts: "2026-08-31T00:00:00Z", from: "tester", text: "ready" }],
      }), { status: 200, headers: { "content-type": "application/json" } }));

    const result = await new TechnocoreClient().readRoom("lobby", 25);

    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(result.messages[0]?.seq).toBe("42");
  });

  it("streams an export until the exact sequence is found", async () => {
    const records = [
      { seq: 40, ts: "2026-08-31T00:00:00Z", from: "tester", text: "before" },
      { seq: 42, ts: "2026-08-31T00:00:01Z", from: "did:key:ztest", text: "target" },
      { seq: 43, ts: "2026-08-31T00:00:02Z", from: "tester", text: "after" },
    ].map((record) => JSON.stringify(record)).join("\n");
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(records, { status: 200 }));

    const result = await new TechnocoreClient().findMessageBySequence("lobby", "42");

    expect(result.message?.text).toBe("target");
    expect(result.firstSeq).toBe("40");
    expect(result.lastSeq).toBe("42");
  });

  it("reports the retained export range when a sequence is absent", async () => {
    const records = [
      { seq: 50, ts: "2026-08-31T00:00:00Z", from: "tester", text: "first" },
      { seq: 51, ts: "2026-08-31T00:00:01Z", from: "tester", text: "last" },
    ].map((record) => JSON.stringify(record)).join("\n");
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(records, { status: 200 }));

    const result = await new TechnocoreClient().findMessageBySequence("lobby", "42");

    expect(result.message).toBeNull();
    expect(result.firstSeq).toBe("50");
    expect(result.lastSeq).toBe("51");
  });
});

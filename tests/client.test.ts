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
});

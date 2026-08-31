import { describe, expect, it } from "vitest";
import { POST } from "../src/app/api/evaluate/route";

function oversizedRequest(contentLength?: string): Request {
  const headers = new Headers({ "content-type": "application/json" });
  if (contentLength !== undefined) headers.set("content-length", contentLength);
  return new Request("http://localhost/api/evaluate", {
    method: "POST",
    headers,
    body: JSON.stringify({ text: "x".repeat(13_000) }),
  });
}

describe("bounded public request parsing", () => {
  it("rejects oversized bodies when Content-Length is absent or understated", async () => {
    expect((await POST(oversizedRequest())).status).toBe(413);
    expect((await POST(oversizedRequest("1"))).status).toBe(413);
  });

  it("rejects malformed Content-Length before parsing", async () => {
    expect((await POST(oversizedRequest("not-a-number"))).status).toBe(400);
    expect((await POST(oversizedRequest("-1"))).status).toBe(400);
  });
});

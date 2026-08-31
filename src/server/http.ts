export class RequestBodyTooLargeError extends Error {}

export async function readBoundedJson(request: Request, maxBytes: number): Promise<unknown> {
  const declared = request.headers.get("content-length");
  if (declared !== null) {
    const declaredBytes = Number(declared);
    if (!Number.isFinite(declaredBytes) || declaredBytes < 0) {
      throw new TypeError("Invalid Content-Length");
    }
    if (declaredBytes > maxBytes) throw new RequestBodyTooLargeError();
  }

  if (!request.body) throw new SyntaxError("Missing request body");
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let received = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > maxBytes) {
        await reader.cancel("Request body is too large").catch(() => undefined);
        throw new RequestBodyTooLargeError();
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(received);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body)) as unknown;
}

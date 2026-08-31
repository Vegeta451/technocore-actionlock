import { NextRequest } from "next/server";
import { isValidRoom } from "@/server/protocol";
import { lookupRoomSequence } from "@/server/scan";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request: NextRequest): Promise<Response> {
  const room = request.nextUrl.searchParams.get("room") ?? "";
  const sequence = request.nextUrl.searchParams.get("seq") ?? "";
  if (!isValidRoom(room)) return Response.json({ error: "Invalid room name" }, { status: 400 });
  if (!/^\d{1,24}$/.test(sequence)) {
    return Response.json({ error: "Sequence must contain 1 to 24 digits" }, { status: 400 });
  }

  try {
    const result = await lookupRoomSequence({ room, sequence, origin: process.env.TECHNOCORE_ORIGIN });
    return Response.json(result, { headers: { "cache-control": "no-store" } });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Sequence lookup failed";
    return Response.json({ error: message }, { status: 502 });
  }
}

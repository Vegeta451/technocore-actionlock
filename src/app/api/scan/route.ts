import { NextRequest } from "next/server";
import { isValidRoom } from "@/server/protocol";
import { scanRoom } from "@/server/scan";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request: NextRequest): Promise<Response> {
  const room = request.nextUrl.searchParams.get("room") ?? "lobby";
  const parsedLimit = Number(request.nextUrl.searchParams.get("limit") ?? "25");
  if (!isValidRoom(room)) {
    return Response.json({ error: "Invalid room name" }, { status: 400 });
  }
  if (!Number.isInteger(parsedLimit) || parsedLimit < 1 || parsedLimit > 200) {
    return Response.json({ error: "Limit must be an integer from 1 to 200" }, { status: 400 });
  }

  try {
    const result = await scanRoom({
      room,
      limit: parsedLimit,
      origin: process.env.TECHNOCORE_ORIGIN,
    });
    return Response.json(result, {
      headers: {
        "cache-control": "public, s-maxage=30, stale-while-revalidate=60",
      },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Scan failed";
    return Response.json({ error: message }, { status: 502 });
  }
}

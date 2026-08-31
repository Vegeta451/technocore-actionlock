export const dynamic = "force-dynamic";

export function GET(): Response {
  return Response.json({
    service: "technocore-actionlock",
    status: "ready",
    mode: "public-inspection",
    localGateway: "MCP only",
    persistence: "none",
  });
}

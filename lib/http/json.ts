/** JSON responses for authenticated APIs are never cacheable. */
import { NextResponse } from "next/server";

export function noStoreJson(
  body: unknown,
  status = 200,
  headers: Record<string, string> = {},
): NextResponse {
  return NextResponse.json(body, {
    status,
    headers: { "Cache-Control": "no-store", ...headers },
  });
}

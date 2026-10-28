/**
 * Tiny static server to preview the GitHub Pages build locally.
 *
 *   npm run build:static     # writes ./out
 *   npm run preview:static   # serves it on http://localhost:4173
 *
 * Mirrors how GitHub Pages serves the folder: `/` → `index.html`,
 * `/mail/` → `mail/index.html`, unknown paths → `404.html`.
 */

import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import path from "node:path";

const ROOT = path.join(process.cwd(), "out");
// `||` not `??`: an empty PORT env var must fall back to the default port.
const PORT = Number(process.env.PORT) || 4173;

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".ico": "image/x-icon",
  ".txt": "text/plain; charset=utf-8",
  ".woff2": "font/woff2",
};

async function resolveFile(urlPath) {
  const clean = decodeURIComponent(urlPath.split("?")[0]);
  const target = path.join(ROOT, clean);
  // Never escape the served folder.
  if (!target.startsWith(ROOT)) return null;

  const candidates = path.extname(clean)
    ? [target]
    : [path.join(target, "index.html"), `${target}.html`];

  for (const candidate of candidates) {
    try {
      const info = await stat(candidate);
      if (info.isFile()) return candidate;
    } catch {
      // keep looking
    }
  }
  return null;
}

const server = createServer(async (req, res) => {
  const file = await resolveFile(req.url ?? "/");

  if (file) {
    try {
      const body = await readFile(file);
      res.writeHead(200, {
        "content-type": TYPES[path.extname(file)] ?? "application/octet-stream",
        "cache-control": "no-cache",
      });
      res.end(body);
      return;
    } catch {
      // fall through to 404
    }
  }

  try {
    const notFound = await readFile(path.join(ROOT, "404.html"));
    res.writeHead(404, { "content-type": "text/html; charset=utf-8" });
    res.end(notFound);
  } catch {
    res.writeHead(404, { "content-type": "text/plain" });
    res.end("404");
  }
});

server.listen(PORT, () => {
  console.log(`[serve-static] ./out → http://localhost:${PORT}`);
});

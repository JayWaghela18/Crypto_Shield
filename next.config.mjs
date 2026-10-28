/** @type {import('next').NextConfig} */

/**
 * Two build flavours from one config:
 *
 *   npm run build         → normal server build (API routes work)
 *   npm run build:static  → `STATIC_EXPORT=1` static export for GitHub Pages
 *                            - `output: "export"` writes a plain `out/` folder
 *                            - `scripts/build-static.mjs` parks `app/api`
 *                              (route handlers need Node; export refuses them)
 *                            - `basePath` matches the repo name so assets and
 *                              links resolve under `/<repo>/` on Pages
 *
 * `NEXT_PUBLIC_STATIC_EXPORT` (set by scripts/build-static.mjs) flips the
 * client over to the localStorage relay in `lib/api/staticRelay.ts`.
 */
const isStaticExport = process.env.STATIC_EXPORT === "1";
const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? "";

if (isStaticExport && basePath) {
  // Inlined into the client bundle by Next when it builds.
  process.env.NEXT_PUBLIC_BASE_PATH = basePath;
}

const nextConfig = {
  reactStrictMode: true,
  ...(isStaticExport
    ? {
        output: "export",
        trailingSlash: true,
        images: { unoptimized: true },
        ...(basePath ? { basePath, assetPrefix: basePath } : {}),
      }
    : {}),
};

export default nextConfig;

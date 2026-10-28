# 🌐 Deploying CryptoShield to GitHub Pages

Step-by-step guide for publishing the lab as a static site on GitHub Pages.

> ← Back to the [project landing page](../README.md)
> · Related: [Setup & Run](./SETUP_AND_RUN.md) · [Troubleshooting](./TROUBLESHOOTING.md)

---

## 1. What GitHub Pages can and cannot host

GitHub Pages serves **static files only** — HTML, CSS, JavaScript. It has no
Node runtime, so the two Next.js API routes that need a server cannot run:

| Route | What it does | On GitHub Pages |
| --- | --- | --- |
| `/api/email` | mail relay (send + receive) | replaced by a **localStorage relay** |
| `/api/keys` | public-key directory + CRL | replaced by the same **localStorage relay** |

CryptoShield ships that replacement in
[`lib/api/staticRelay.ts`](../lib/api/staticRelay.ts): the exact same routes,
status codes and validation, backed by `localStorage` instead of a server.
Every cryptographic operation (RSA-OAEP, RSA-PSS, AES-256-GCM, SHA-256,
DOMPurify) still runs in the browser exactly as it does locally — nothing is
weakened, because none of it ever depended on the server.

**What that means in practice:**

- ✅ Full lab works: sign-in / registration / quick demo, compose, send,
  receive, secure E2EE mail, Attack Lab, transport inspector, key manager, CRL.
- ⚠️ Data is **per browser, per origin**. Visitors see their own demo mailbox;
  there is no shared server inbox and no sync between machines.
- ⚠️ Inspector packets carry an `x-relay: localStorage` header so the wire view
  never pretends bytes travelled to a server.
- 🧑‍💻 Want the shared-server version (same inbox for everyone)? Deploy the
  normal build to any Node host — see [§6](#6-alternative-full-server-deploy).

---

## 2. Prerequisites

| Requirement | Notes |
| --- | --- |
| **Node.js 18+** (20 LTS recommended) | Same as local development. |
| **A GitHub account + repository** | The project is `JayWaghela18/Crypto_Shield`. |
| **Pages enabled for the repo** | Settings → Pages → Source: **GitHub Actions** (see §4). |
| **Push access to `main`** | The workflow runs on every push to `main`. |

Everything needed for the static build is already in the repository — no
extra dependencies, no environment secrets.

---

## 3. Build the static site locally (optional but recommended)

```bash
npm install            # once
npm run build:static   # writes a plain static folder to ./out
npm run preview:static # serve ./out on http://localhost:4173
```

Open **http://localhost:4173** and click through: sign in with a demo profile,
send a message, run an Attack Lab simulation. The transport inspector should
show packets with the `x-relay: localStorage` header — that is how you know the
static relay (not a server) is answering.

What `npm run build:static` does:

1. clears `.next/` and `out/`;
2. **parks `app/api/`** out of the tree for the duration of the build
   (`output: "export"` refuses route handlers that need Node) and restores it
   afterwards, even on Ctrl+C;
3. runs `next build` with:
   - `STATIC_EXPORT=1` → `output: "export"` in
     [`next.config.mjs`](../next.config.mjs),
   - `NEXT_PUBLIC_STATIC_EXPORT=1` → the client uses
     [`lib/api/staticRelay.ts`](../lib/api/staticRelay.ts) instead of `fetch`,
   - `NEXT_PUBLIC_BASE_PATH` → the sub-path the site is served from
     (`/Crypto_Shield` for this repository);
4. emits `out/` — the folder GitHub Pages publishes.

`npm run build` (the normal server build) is unchanged and still contains the
real API routes.

---

## 4. Deploy with the included GitHub Actions workflow

The workflow [`.github/workflows/deploy-pages.yml`](../.github/workflows/deploy-pages.yml)
builds the static bundle and publishes `out/`.

### 4.1 One-time repository setting

1. Open the repository on GitHub → **Settings → Pages**.
2. Under **Build and deployment → Source**, choose **GitHub Actions**.
   (If it is set to "Deploy from a branch", the workflow cannot publish.)

### 4.2 Push

```bash
git add .
git commit -m "Deploy CryptoShield to GitHub Pages"
git push origin main
```

### 4.3 Watch it run

**Actions** tab → *Deploy to GitHub Pages* → two jobs:

| Job | What it does |
| --- | --- |
| `Build static export` | `npm ci` → `npm run build:static` with `NEXT_PUBLIC_BASE_PATH=/<repo>` → uploads `out/` as the Pages artifact |
| `Deploy to GitHub Pages` | publishes the artifact with `actions/deploy-pages` |

### 4.4 Open the site

After the run turns green, the job summary shows the URL:

```
https://jaywaghela18.github.io/Crypto_Shield/
```

(The environment page in the repo also lists it under **github-pages**.)

> 🔄 **Re-deploys:** every push to `main` republishes. To deploy a different
> branch, change `branches: [main]` in the workflow.

---

## 5. How the static build works (one paragraph per piece)

- **[`next.config.mjs`](../next.config.mjs)** — `output: "export"` turns the
  build into plain files; `trailingSlash: true` makes `/mail/` resolve to
  `/mail/index.html` on Pages; `basePath`/`assetPrefix` prefix every asset with
  `/<repo>` so links work under the repository sub-path.
- **[`scripts/build-static.mjs`](../scripts/build-static.mjs)** — sets the
  build flags, moves `app/api` aside (and back), runs `next build`.
- **[`lib/api/staticRelay.ts`](../lib/api/staticRelay.ts)** — a `fetch`
  drop-in implementing `/api/email` and `/api/keys` on top of `localStorage`,
  seeded with the same demo mailbox the server seeds
  ([`lib/server/demoSeed.ts`](../lib/server/demoSeed.ts)).
- **[`lib/api/emailClient.ts`](../lib/api/emailClient.ts)** — the single place
  the UI performs requests; it routes to the relay when the static flag is on,
  so no component needed to know which deployment it is on.

---

## 6. Alternative: full server deploy

If you want the *shared* mailbox (one server, everyone sees the same inbox),
GitHub Pages cannot host it — use any Node host instead:

```bash
npm ci
npm run build   # server build with the real /api routes
npm start       # next start → listens on PORT (default 3000)
```

Render, Railway, Fly.io, a VPS, or `next start` behind a reverse
proxy all work: the app needs **no environment variables and no database**
(it keeps state in memory + `.data/`). Do **not** expose the demo to the public
internet as a production service — the "unsafe" engine is deliberately
insecure.

---

## 7. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| Blank page / `404` on `/_next/...` assets | Site is served from a sub-path but `NEXT_PUBLIC_BASE_PATH` was empty | Build with `NEXT_PUBLIC_BASE_PATH=/<repo>` (the workflow does this) |
| Deploy job fails with *"No pages found"* or an artifact error | Pages source is not "GitHub Actions" | Settings → Pages → Source → **GitHub Actions** |
| The 404 page shows for `/mail` | Static server without directory indexes | Pages handles this (that is why `trailingSlash: true`); locally use `npm run preview:static` |
| Inbox is empty for a visitor | By design: each browser has its own localStorage relay | Run a demo profile or the Attack Lab to populate it |
| Changes do not appear after pushing | CDN cache on the Pages URL | Hard-refresh; Actions runs are usually live within a minute |
| `Error: export const dynamic = "force-dynamic" ... cannot be used with "output: export"` | `app/api` was present during a static build | Always build with `npm run build:static` (it parks `app/api` for you) |

---

## 8. Checklist before you publish

- [ ] `npm run typecheck`, `npm test`, `npm run build` all pass locally
- [ ] `npm run build:static` writes `out/` and `npm run preview:static` looks right
- [ ] Pages source is set to **GitHub Actions**
- [ ] Push to `main` → workflow green → site opens at the `github.io` URL
- [ ] On the live site: sign in → send → read → run one Attack Lab simulation

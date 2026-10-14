/**
 * Phase 1 home — split-screen shell:
 *
 *  ┌───────────────────────────┬──────────────────────────────┐
 *  │  Mailbox (left)           │  Transport & Packet          │
 *  │  Inbox / Sent / Compose   │  Inspector (right)           │
 *  └───────────────────────────┴──────────────────────────────┘
 *
 * Both panes are client components sharing the app state providers from
 * app/layout.tsx.
 */

import Mailbox from "@/components/mailbox/Mailbox";
import TransportInspector from "@/components/inspector/TransportInspector";

export default function HomePage() {
  return (
    <div className="grid h-full grid-cols-1 lg:grid-cols-[minmax(0,57fr)_minmax(0,43fr)]">
      {/* Left: mailbox UI */}
      <section className="flex min-h-0 flex-col overflow-hidden border-b border-slate-800 lg:border-b-0 lg:border-r">
        <Mailbox />
      </section>

      {/* Right: live wire inspector */}
      <aside className="flex min-h-0 flex-col overflow-hidden bg-slate-950">
        <TransportInspector />
      </aside>
    </div>
  );
}

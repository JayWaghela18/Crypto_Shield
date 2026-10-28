/**
 * Mailbox — persisted inbox/sent/compose (left) and wire inspector (right).
 *
 * The inspector still records every request the browser makes, so a secure
 * send visibly contains only ciphertext while an unsafe send contains the
 * plaintext body.
 */

import type { Metadata } from "next";
import Mailbox from "@/components/mailbox/Mailbox";
import TransportInspector from "@/components/inspector/TransportInspector";

export const metadata: Metadata = { title: "Mailbox" };

export default function MailPage() {
  return (
    <div className="grid h-full min-h-0 grid-cols-1 lg:grid-cols-[minmax(0,57fr)_minmax(0,43fr)]">
      <section className="flex min-h-0 flex-col overflow-hidden border-b border-slate-800 lg:border-b-0 lg:border-r">
        <Mailbox />
      </section>

      <aside className="flex min-h-0 flex-col overflow-hidden bg-slate-950">
        <TransportInspector />
      </aside>
    </div>
  );
}

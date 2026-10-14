"use client";

/**
 * Composes all context providers in dependency order:
 *
 *   SecurityMode  → global unsafe/secure flag
 *     Transport    → live wire-packet log (reads nothing above)
 *       Audit      → detected-incident log (inspector report export)
 *         KeyVault  → optional imported third-party key material
 *           UserProfile → Web Crypto keypairs (browser-only)
 *             MailStore → mailbox actions (reads mode + transport)
 */

import type { ReactNode } from "react";
import { SecurityModeProvider } from "@/store/SecurityModeContext";
import { TransportProvider } from "@/store/TransportContext";
import { AuditProvider } from "@/store/AuditContext";
import { KeyVaultProvider } from "@/store/KeyVaultContext";
import { UserProfileProvider } from "@/store/UserProfileContext";
import { MailStoreProvider } from "@/store/MailStoreContext";

export default function AppProviders({ children }: { children: ReactNode }) {
  return (
    <SecurityModeProvider>
      <TransportProvider>
        <AuditProvider>
          <KeyVaultProvider>
            <UserProfileProvider>
              <MailStoreProvider>{children}</MailStoreProvider>
            </UserProfileProvider>
          </KeyVaultProvider>
        </AuditProvider>
      </TransportProvider>
    </SecurityModeProvider>
  );
}

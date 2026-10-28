"use client";

/**
 * Composes every context provider in dependency order:
 *
 *   SecurityMode  → global unsafe/secure flag
 *     Transport    → live wire-packet + crypto-step log
 *       Audit      → detected-incident log (inspector report export)
 *         KeyVault  → optional imported third-party key material
 *           Auth      → local accounts, RSA keys, session
 *             MailStore → mailbox actions (reads the active account)
 */

import type { ReactNode } from "react";
import { SecurityModeProvider } from "@/store/SecurityModeContext";
import { TransportProvider } from "@/store/TransportContext";
import { AuditProvider } from "@/store/AuditContext";
import { KeyVaultProvider } from "@/store/KeyVaultContext";
import { AuthProvider } from "@/store/AuthContext";
import { MailStoreProvider } from "@/store/MailStoreContext";

export default function AppProviders({ children }: { children: ReactNode }) {
  return (
    <SecurityModeProvider>
      <TransportProvider>
        <AuditProvider>
          <KeyVaultProvider>
            <AuthProvider>
              <MailStoreProvider>{children}</MailStoreProvider>
            </AuthProvider>
          </KeyVaultProvider>
        </AuditProvider>
      </TransportProvider>
    </SecurityModeProvider>
  );
}

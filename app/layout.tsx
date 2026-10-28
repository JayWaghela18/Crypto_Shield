import type { Metadata } from "next";
import "./globals.css";
import AppProviders from "@/store/AppProviders";
import Navbar from "@/components/Navbar";

export const metadata: Metadata = {
  title: "CryptoShield — Secure Mail Operations",
  description:
    "Cyber command center for end-to-end encrypted email: RSA-2048 identities, AES-256-GCM transport, live packet inspection and attack simulations.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen">
        <AppProviders>
          {/* Decorative cyber grid behind the whole command center */}
          <div
            aria-hidden
            className="pointer-events-none fixed inset-0 -z-10 bg-cyber-grid bg-grid opacity-[0.35]"
          />
          <div className="flex min-h-screen flex-col">
            <Navbar />
            {children}
          </div>
        </AppProviders>
      </body>
    </html>
  );
}

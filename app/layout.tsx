import type { Metadata } from "next";
import "./globals.css";
import AppProviders from "@/store/AppProviders";
import Navbar from "@/components/Navbar";

export const metadata: Metadata = {
  title: "CryptoShield — Email Transport Security Lab",
  description:
    "Interactive demonstration of email transport vulnerabilities (spoofing, plaintext, Stored XSS) vs. end-to-end cryptographic protection (Phase 1).",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="antialiased">
        <AppProviders>
          {/* Global nav with the Security Mode Switch */}
          <Navbar />
          <main className="h-[calc(100vh-4rem)]">{children}</main>
        </AppProviders>
      </body>
    </html>
  );
}

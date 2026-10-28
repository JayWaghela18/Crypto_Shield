/**
 * Application shell. Authentication is client-side (see `AuthProvider`); the
 * command bar mounts the login modal whenever no account is active.
 */
export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <main className="flex min-h-0 flex-1 flex-col">
      {children}
    </main>
  );
}

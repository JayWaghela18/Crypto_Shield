/**
 * Mailbox shell. The mail store is app-wide (`AppProviders`) and reads the
 * active account, so this layout only provides the flex container.
 */
export default function MailLayout({ children }: { children: React.ReactNode }) {
  return <div className="flex min-h-0 flex-1 flex-col">{children}</div>;
}

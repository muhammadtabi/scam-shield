export default function Privacy() {
  return (
    <main className="legal-page grid-bg">
      <article className="legal-content glass">
        <p className="legal-eyebrow">Scam Shield</p>
        <h1 className="page-title">Privacy Policy</h1>
        <p className="page-subtitle">Last updated: October 27, 2026</p>

        <h2>What we access</h2>
        <p>When you connect Gmail, Scam Shield requests the read-only Gmail permission required to inspect messages for scam detection. We do not send, edit, delete, or manage your Gmail messages.</p>

        <h2>How email data is used</h2>
        <p>Email content is processed transiently in memory only to classify messages and explain detection results. Scam Shield does not store full email body content, and does not sell, advertise against, or share your email content with third parties.</p>

        <h2>Storage and security</h2>
        <p>Your Scam Shield account and mailbox connection are stored separately by your user ID, along with only basic scan metadata (such as sender, subject, message ID, risk verdict, and explanation). OAuth tokens and optional read-only IMAP App Passwords are stored encrypted per user ID so the monitor can inspect your inbox in read-only mode. Disconnecting immediately disables monitoring and deletes stored credentials.</p>

        <h2>Your choices</h2>
        <p>You can disconnect Gmail from the dashboard at any time. You can also revoke Scam Shield access from your Google Account security settings.</p>

        <a className="legal-back-link" href="/">← Back to Scam Shield</a>
      </article>
    </main>
  )
}

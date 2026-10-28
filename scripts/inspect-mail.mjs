/**
 * Read-only inspector for the Phase 2 mail pipeline.
 *
 * Usage: node --env-file=.env scripts/inspect-mail.mjs
 *
 * Prints the newest messages with their stored body, wrapped AES key and
 * signature so you can confirm the server never sees plaintext in Secure Mode.
 */
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

try {
  const emails = await prisma.email.findMany({
    take: 10,
    orderBy: { createdAt: "desc" },
    include: {
      sender: { select: { email: true } },
      recipient: { select: { email: true } },
    },
  });

  if (emails.length === 0) {
    console.log("No messages stored yet.");
  }

  for (const email of emails) {
    console.log(
      JSON.stringify(
        {
          id: email.id,
          from: email.sender.email,
          to: email.recipient.email,
          subject: email.subject,
          isSecureMode: email.isSecureMode,
          storedBodyPrefix: email.body.slice(0, 96),
          storedBodyLength: email.body.length,
          ciphertext: email.isSecureMode
            ? email.encryptedSymmetricKey
              ? "present"
              : "MISSING"
            : null,
          wrappedKey: email.encryptedSymmetricKey?.slice(0, 32) ?? null,
          signature: email.signature?.slice(0, 32) ?? null,
          createdAt: email.createdAt.toISOString(),
        },
        null,
        2,
      ),
    );
  }
} finally {
  await prisma.$disconnect();
}

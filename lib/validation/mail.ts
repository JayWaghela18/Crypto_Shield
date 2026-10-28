/**
 * Validation for the persisted mail API.
 *
 * Secure-mode bodies are opaque base64 ciphertext, so the server can only
 * enforce shape and size — not content. Unsafe mode is plaintext HTML and is
 * explicitly marked as such.
 */

import { z } from "zod";
import { emailField } from "@/lib/validation/auth";

export const MAX_MAIL_BODY_CHARS = 100_000;
export const MAX_ENVELOPE_FIELD_CHARS = 8_192;

const base64Field = z
  .string()
  .min(1, "Required")
  .max(MAX_ENVELOPE_FIELD_CHARS, "Envelope field is too large")
  .regex(/^[A-Za-z0-9+/]+={0,2}$/, "Must be base64");

export const sendMailSchema = z
  .object({
    recipient: emailField,
    subject: z.string().trim().max(200, "Subject must be at most 200 characters"),
    body: z
      .string()
      .min(1, "Message body is required")
      .max(MAX_MAIL_BODY_CHARS, "Message body is too large"),
    isSecureMode: z.boolean(),
    encryptedSymmetricKey: z.string().optional(),
    signature: z.string().optional(),
  })
  .superRefine((value, ctx) => {
    if (!value.isSecureMode) return;

    if (!value.encryptedSymmetricKey) {
      ctx.addIssue({
        code: "custom",
        path: ["encryptedSymmetricKey"],
        message: "Secure messages require an RSA-wrapped AES key",
      });
    } else {
      const parsed = base64Field.safeParse(value.encryptedSymmetricKey);
      if (!parsed.success) {
        ctx.addIssue({
          code: "custom",
          path: ["encryptedSymmetricKey"],
          message: parsed.error.issues[0]?.message ?? "Invalid wrapped key",
        });
      }
    }

    if (!value.signature) {
      ctx.addIssue({
        code: "custom",
        path: ["signature"],
        message: "Secure messages require an RSA-PSS signature",
      });
    } else {
      const parsed = base64Field.safeParse(value.signature);
      if (!parsed.success) {
        ctx.addIssue({
          code: "custom",
          path: ["signature"],
          message: parsed.error.issues[0]?.message ?? "Invalid signature",
        });
      }
    }

    // Minimum: 12-byte IV + 16-byte GCM tag + some ciphertext.
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value.body) || value.body.length < 40) {
      ctx.addIssue({
        code: "custom",
        path: ["body"],
        message: "Secure message body must be base64 ciphertext",
      });
    }
  });

export type SendMailInput = z.infer<typeof sendMailSchema>;

export const lookupQuerySchema = z.object({
  email: emailField,
});

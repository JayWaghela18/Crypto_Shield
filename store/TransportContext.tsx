"use client";

/**
 * Live transport log — every HTTP message captured by emailClient is pushed
 * here, and the TransportInspector renders the list newest-first in real time.
 */

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import type { CryptoStep, CryptoStepInput, TransportPacket } from "@/lib/types";

/** Keep the log bounded so long sessions stay responsive. */
const MAX_PACKETS = 100;
const MAX_STEPS = 60;

interface TransportContextValue {
  packets: TransportPacket[];
  /** Append a captured packet (called from the fetch wrapper). */
  recordPacket: (packet: TransportPacket) => void;
  /**
   * Cryptographic execution log (Phase 2) — every engine step (AES keygen,
   * RSA wrap, hashing, signing, verification…) lands here and is rendered
   * as a numbered timeline in the inspector.
   */
  cryptoSteps: CryptoStep[];
  recordCryptoStep: (step: CryptoStepInput) => void;
  /** Empty both logs (inspector "Clear" button). */
  clearPackets: () => void;
}

const TransportContext = createContext<TransportContextValue | null>(null);

export function TransportProvider({ children }: { children: ReactNode }) {
  const [packets, setPackets] = useState<TransportPacket[]>([]);
  const [cryptoSteps, setCryptoSteps] = useState<CryptoStep[]>([]);

  const recordPacket = useCallback((packet: TransportPacket) => {
    setPackets((prev) => [packet, ...prev].slice(0, MAX_PACKETS));
  }, []);

  // Steps append oldest→newest so the inspector reads top-down in pipeline
  // order (AES key generation → RSA encryption → hashing → signing → …).
  const recordCryptoStep = useCallback((step: CryptoStepInput) => {
    setCryptoSteps((prev) =>
      [...prev, { ...step, id: crypto.randomUUID(), timestamp: Date.now() }].slice(
        -MAX_STEPS,
      ),
    );
  }, []);

  const clearPackets = useCallback(() => {
    setPackets([]);
    setCryptoSteps([]);
  }, []);

  const value = useMemo<TransportContextValue>(
    () => ({ packets, cryptoSteps, recordPacket, recordCryptoStep, clearPackets }),
    [packets, cryptoSteps, recordPacket, recordCryptoStep, clearPackets],
  );

  return <TransportContext.Provider value={value}>{children}</TransportContext.Provider>;
}

/** Access the live packet log. Throws if used outside the provider. */
export function useTransport(): TransportContextValue {
  const ctx = useContext(TransportContext);
  if (!ctx) throw new Error("useTransport must be used within TransportProvider");
  return ctx;
}

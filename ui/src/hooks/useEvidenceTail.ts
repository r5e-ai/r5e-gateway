// useEvidenceTail — WebSocket hook for `GET /v1/evidence/tail`.
//
// Connects with optional `kind`, `session`, and `actor` query-string filters,
// handles `{"type":"record","record":...}` and `{"type":"ping"}` frames, and
// exposes `mergeEvidenceRows` for subscribe-then-fetch deduplication by `ref`.

import { useEffect, useRef, useState } from "react";

import { apiPaths } from "~/lib/apiPaths";
import type { EvidenceRecordEntry, LiveTailFrame } from "~/lib/evidenceTypes";

export type LiveTailStatus =
  | "off"
  | "connecting"
  | "connected"
  | "not_capturing"
  | "unavailable"
  | "error";

export interface EvidenceTailFilters {
  kind?: string;
  session?: string;
  actor?: string;
}

const MAX_TAIL_BUFFER = 500;

/**
 * Deduplicate live-tail records against fetched list rows by `ref`, keeping
 * live records ahead of older pages while preserving unique `ref` ordering.
 */
export function mergeEvidenceRows(
  liveRecords: readonly EvidenceRecordEntry[],
  fetchedRecords: readonly EvidenceRecordEntry[],
): EvidenceRecordEntry[] {
  if (liveRecords.length === 0) return fetchedRecords.slice();
  const seen = new Set<string>();
  const merged: EvidenceRecordEntry[] = [];
  for (const r of liveRecords) {
    if (!seen.has(r.ref)) {
      seen.add(r.ref);
      merged.push(r);
    }
  }
  for (const r of fetchedRecords) {
    if (!seen.has(r.ref)) {
      seen.add(r.ref);
      merged.push(r);
    }
  }
  return merged;
}

function buildWsUrl(filters: EvidenceTailFilters): string {
  const path = apiPaths.liveTail(filters);
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}${path}`;
}

export function useEvidenceTail(
  enabled: boolean,
  filters: EvidenceTailFilters,
  onConnected?: () => void,
) {
  const [status, setStatus] = useState<LiveTailStatus>("off");
  const [statusDetail, setStatusDetail] = useState<string | null>(null);
  const [liveRecords, setLiveRecords] = useState<EvidenceRecordEntry[]>([]);
  const onConnectedRef = useRef(onConnected);
  onConnectedRef.current = onConnected;

  useEffect(() => {
    if (!enabled) {
      setStatus("off");
      setStatusDetail(null);
      setLiveRecords([]);
      return;
    }

    let cancelled = false;
    let ws: WebSocket | null = null;
    setStatus("connecting");
    setStatusDetail(null);
    setLiveRecords([]);

    const wsUrl = buildWsUrl(filters);
    try {
      ws = new WebSocket(wsUrl);
    } catch {
      setStatus("unavailable");
      setStatusDetail("WebSocket unavailable in this environment.");
      return;
    }

    ws.onopen = () => {
      if (cancelled) return;
      setStatus("connected");
      setStatusDetail(null);
      // Subscribe-then-fetch: trigger a fresh list fetch once subscribed so no
      // records between initial HTTP fetch and WS open are missed.
      onConnectedRef.current?.();
    };

    ws.onmessage = (evt) => {
      if (cancelled || typeof evt.data !== "string") return;
      let frame: LiveTailFrame | { type?: string; error?: string; message?: string };
      try {
        frame = JSON.parse(evt.data) as LiveTailFrame;
      } catch {
        return;
      }
      if (frame.type === "ping") {
        ws?.send(JSON.stringify({ type: "pong" }));
        return;
      }
      if (frame.type === "record" && "record" in frame && frame.record?.ref) {
        const rec = frame.record;
        setLiveRecords((prev) => {
          if (prev.some((r) => r.ref === rec.ref)) return prev;
          return [rec, ...prev].slice(0, MAX_TAIL_BUFFER);
        });
      }
    };

    ws.onerror = () => {
      if (cancelled) return;
      // Probe handshake error via HTTP to distinguish 503 ERR_NOT_CAPTURING,
      // 426 Upgrade Required, 404, and 400 cleanly.
      const httpPath = apiPaths.liveTail(filters);
      void fetch(httpPath, { credentials: "include" })
        .then(async (resp) => {
          if (cancelled) return;
          const body = (await resp.json().catch(() => null)) as {
            error?: string;
            message?: string;
          } | null;
          if (resp.status === 503 || body?.error === "ERR_NOT_CAPTURING") {
            setStatus("not_capturing");
            setStatusDetail("Gateway node is not currently capturing live evidence (503).");
          } else if (resp.status === 404) {
            setStatus("unavailable");
            setStatusDetail("Live-tail stream not found (404).");
          } else if (resp.status === 400) {
            setStatus("error");
            setStatusDetail(body?.message ?? "Invalid live-tail filter (400).");
          } else if (resp.status === 426) {
            setStatus("unavailable");
            setStatusDetail("WebSocket upgrade required (426).");
          } else {
            setStatus("unavailable");
            setStatusDetail("Live-tail connection unavailable.");
          }
        })
        .catch(() => {
          if (!cancelled) {
            setStatus("unavailable");
            setStatusDetail("Live-tail connection unavailable.");
          }
        });
    };

    ws.onclose = (evt) => {
      if (cancelled) return;
      if (evt.code === 1000) {
        setStatus("off");
      } else {
        setStatus((cur) => (cur === "connected" || cur === "connecting" ? "unavailable" : cur));
      }
    };

    return () => {
      cancelled = true;
      ws?.close(1000);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, filters.kind, filters.session, filters.actor]);

  return { status, statusDetail, liveRecords };
}

// useEvidenceTail — WebSocket hook for `GET /v1/evidence/tail`.
//
// Connects with optional `kind`, `session`, and `actor` query-string filters,
// handles `{"type":"record","record":...}` and `{"type":"ping"}` frames,
// reconnects with bounded exponential backoff (1s -> 2s -> 4s -> 8s) on
// transient drops, stops on terminal errors (400/401/403/404/503), and
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
export const BACKOFF_BASE_MS = 1_000;
export const BACKOFF_MAX_MS = 8_000;

export function nextBackoffDelayMs(attempt: number): number {
  return Math.min(BACKOFF_MAX_MS, BACKOFF_BASE_MS * 2 ** Math.max(0, attempt));
}

export interface ProbeOutcome {
  status: LiveTailStatus;
  detail: string;
  shouldReconnect: boolean;
}

/**
 * Interpret an HTTP probe response from `GET /v1/evidence/tail` after a
 * WebSocket drop. A healthy node answers a non-WS GET with `426`, which
 * indicates a transient connection loss rather than a misconfigured route.
 */
export function classifyTailProbeResponse(
  httpStatus: number,
  body?: { error?: string; message?: string } | null,
): ProbeOutcome {
  if (httpStatus === 503 || body?.error === "ERR_NOT_CAPTURING") {
    return {
      status: "not_capturing",
      detail: "Gateway node is not currently capturing live evidence (503).",
      shouldReconnect: false,
    };
  }
  if (httpStatus === 401 || httpStatus === 403) {
    return {
      status: "error",
      detail: `Not authorized to stream live evidence (${httpStatus}).`,
      shouldReconnect: false,
    };
  }
  if (httpStatus === 404) {
    return {
      status: "unavailable",
      detail: "Live-tail stream not found (404).",
      shouldReconnect: false,
    };
  }
  if (httpStatus === 400) {
    return {
      status: "error",
      detail: body?.message ?? "Invalid live-tail filter (400).",
      shouldReconnect: false,
    };
  }
  if (httpStatus === 426) {
    return {
      status: "unavailable",
      detail: "Connection lost — reconnecting…",
      shouldReconnect: true,
    };
  }
  return {
    status: "unavailable",
    detail: "Connection lost — reconnecting…",
    shouldReconnect: true,
  };
}

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
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let attempt = 0;
    let probeInFlight = false;

    setLiveRecords([]);

    function scheduleReconnect(): void {
      if (cancelled || reconnectTimer !== null) return;
      const delay = nextBackoffDelayMs(attempt);
      attempt += 1;
      reconnectTimer = setTimeout(() => {
        reconnectTimer = null;
        if (!cancelled) connect();
      }, delay);
    }

    function probeAndMaybeReconnect(): void {
      if (cancelled || probeInFlight) return;
      probeInFlight = true;
      const httpPath = apiPaths.liveTail(filters);
      void fetch(httpPath, { credentials: "include" })
        .then(async (resp) => {
          probeInFlight = false;
          if (cancelled) return;
          const body = (await resp.json().catch(() => null)) as {
            error?: string;
            message?: string;
          } | null;
          const outcome = classifyTailProbeResponse(resp.status, body);
          setStatus(outcome.status);
          setStatusDetail(outcome.detail);
          if (outcome.shouldReconnect) {
            scheduleReconnect();
          }
        })
        .catch(() => {
          probeInFlight = false;
          if (cancelled) return;
          setStatus("unavailable");
          setStatusDetail("Connection lost — reconnecting…");
          scheduleReconnect();
        });
    }

    function connect(): void {
      if (cancelled) return;
      setStatus("connecting");

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
        attempt = 0;
        setStatus("connected");
        setStatusDetail(null);
        // Subscribe-then-fetch: refresh list once subscribed so no records
        // between HTTP list fetch and WS open are missed.
        onConnectedRef.current?.();
      };

      ws.onmessage = (evt) => {
        if (cancelled || typeof evt.data !== "string") return;
        let frame: LiveTailFrame | { type?: string };
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
        probeAndMaybeReconnect();
      };

      ws.onclose = (evt) => {
        if (cancelled) return;
        if (evt.code === 1000) {
          setStatus("off");
          return;
        }
        probeAndMaybeReconnect();
      };
    }

    connect();

    return () => {
      cancelled = true;
      if (reconnectTimer !== null) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      ws?.close(1000);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, filters.kind, filters.session, filters.actor]);

  return { status, statusDetail, liveRecords };
}

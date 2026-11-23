// toolArgs — Structured extraction, parsing, and plain-text formatting of
// ToolCall / ToolResult arguments (both inline payload fields and external
// contentRef JSON/text blobs). All values are returned as plain strings for
// safe React text rendering (never HTML).

import type { EvidenceEnvelopePayload } from "~/lib/evidenceTypes";

export interface ToolArgEntry {
  key: string;
  value: unknown;
  display: string;
  rawCopy: string;
  isComplex: boolean;
}

export interface ParsedToolArgs {
  source: "inline" | "content" | "details" | "none";
  entries: ToolArgEntry[];
  rawJson: string | null;
  rawText: string | null;
  nonJsonNote: string | null;
}

const PREFERRED_KEY_ORDER = [
  "commandLine",
  "command",
  "cmd",
  "script",
  "path",
  "target",
  "topic",
  "mode",
  "query",
  "url",
  "argv",
  "args",
  "program",
  "exitCode",
  "outcome",
];

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function sortArgKeys(keys: string[]): string[] {
  return [...keys].sort((a, b) => {
    const ia = PREFERRED_KEY_ORDER.indexOf(a);
    const ib = PREFERRED_KEY_ORDER.indexOf(b);
    if (ia >= 0 && ib >= 0) return ia - ib;
    if (ia >= 0) return -1;
    if (ib >= 0) return 1;
    return a.localeCompare(b);
  });
}

function formatSingleValue(value: unknown): {
  display: string;
  rawCopy: string;
  isComplex: boolean;
} {
  if (value === null) return { display: "null", rawCopy: "null", isComplex: false };
  if (value === undefined) return { display: "—", rawCopy: "", isComplex: false };
  if (typeof value === "string") {
    return { display: value, rawCopy: value, isComplex: value.includes("\n") };
  }
  if (typeof value === "number" || typeof value === "boolean") {
    const s = String(value);
    return { display: s, rawCopy: s, isComplex: false };
  }
  if (Array.isArray(value)) {
    const allPrimitive = value.every(
      (item) =>
        item === null ||
        typeof item === "string" ||
        typeof item === "number" ||
        typeof item === "boolean",
    );
    const json = JSON.stringify(value, null, 2);
    if (allPrimitive && value.length <= 6) {
      return {
        display: JSON.stringify(value),
        rawCopy: json,
        isComplex: false,
      };
    }
    return { display: json, rawCopy: json, isComplex: true };
  }
  const json = JSON.stringify(value, null, 2);
  return { display: json, rawCopy: json, isComplex: true };
}

function entriesFromObject(obj: Record<string, unknown>): ToolArgEntry[] {
  const keys = sortArgKeys(Object.keys(obj));
  return keys.map((key) => {
    const value = obj[key];
    const formatted = formatSingleValue(value);
    return {
      key,
      value,
      display: formatted.display,
      rawCopy: formatted.rawCopy,
      isComplex: formatted.isComplex,
    };
  });
}

/**
 * Extracts structured arguments from inline ToolCall / ToolResult body fields:
 *   1. `body.args` / `body.arguments` / `body.input`
 *   2. `body.command`
 *   3. `body.details` scalar/structured metadata
 */
export function extractInlineToolArgs(
  payload: EvidenceEnvelopePayload | null,
): ParsedToolArgs {
  if (!payload?.body) {
    return { source: "none", entries: [], rawJson: null, rawText: null, nonJsonNote: null };
  }
  const body = payload.body;

  for (const field of ["args", "arguments", "input"] as const) {
    const candidate = body[field];
    if (isPlainObject(candidate) && Object.keys(candidate).length > 0) {
      return {
        source: "inline",
        entries: entriesFromObject(candidate),
        rawJson: JSON.stringify(candidate, null, 2),
        rawText: null,
        nonJsonNote: null,
      };
    }
    if (typeof candidate === "string" && candidate.trim().length > 0) {
      return parseContentBlobArgs(candidate, "application/json", "inline");
    }
    if (Array.isArray(candidate) && candidate.length > 0) {
      const formatted = formatSingleValue(candidate);
      return {
        source: "inline",
        entries: [{ key: field, value: candidate, ...formatted }],
        rawJson: JSON.stringify(candidate, null, 2),
        rawText: null,
        nonJsonNote: null,
      };
    }
  }

  if (typeof body.command === "string" && body.command.trim().length > 0) {
    const obj = { command: body.command.trim() };
    return {
      source: "inline",
      entries: entriesFromObject(obj),
      rawJson: JSON.stringify(obj, null, 2),
      rawText: null,
      nonJsonNote: null,
    };
  }

  if (isPlainObject(body.details) && Object.keys(body.details).length > 0) {
    return {
      source: "details",
      entries: entriesFromObject(body.details),
      rawJson: JSON.stringify(body.details, null, 2),
      rawText: null,
      nonJsonNote: null,
    };
  }

  return { source: "none", entries: [], rawJson: null, rawText: null, nonJsonNote: null };
}

function looksBinary(text: string): boolean {
  const sample = text.slice(0, 512);
  let nonPrintable = 0;
  for (let i = 0; i < sample.length; i++) {
    const code = sample.charCodeAt(i);
    if (code === 0 || (code < 32 && code !== 9 && code !== 10 && code !== 13)) {
      nonPrintable++;
    }
  }
  return sample.length > 0 && nonPrintable / sample.length > 0.1;
}

/**
 * Parses an external `contentRef` blob (or inline JSON string) into structured
 * key-value entries, handling plain text and binary payloads gracefully.
 */
export function parseContentBlobArgs(
  rawText: string,
  mediaType?: string | null,
  source: "content" | "inline" = "content",
): ParsedToolArgs {
  const mt = (mediaType ?? "").toLowerCase();
  const trimmed = rawText.trim();

  if (
    (mt.startsWith("image/") ||
      mt.startsWith("audio/") ||
      mt.startsWith("video/") ||
      mt === "application/pdf") &&
    !trimmed.startsWith("{") &&
    !trimmed.startsWith("[")
  ) {
    return {
      source,
      entries: [],
      rawJson: null,
      rawText: null,
      nonJsonNote: `Binary content (${mediaType}) cannot be displayed as structured arguments.`,
    };
  }

  if (trimmed.length === 0) {
    return {
      source,
      entries: [],
      rawJson: null,
      rawText: "",
      nonJsonNote: "Attached content is empty.",
    };
  }

  if (looksBinary(rawText)) {
    return {
      source,
      entries: [],
      rawJson: null,
      rawText: null,
      nonJsonNote: "Binary content cannot be displayed as structured arguments.",
    };
  }

  try {
    const parsed: unknown = JSON.parse(trimmed);
    if (isPlainObject(parsed)) {
      return {
        source,
        entries: entriesFromObject(parsed),
        rawJson: JSON.stringify(parsed, null, 2),
        rawText: null,
        nonJsonNote: null,
      };
    }
    const formatted = formatSingleValue(parsed);
    return {
      source,
      entries: [{ key: "value", value: parsed, ...formatted }],
      rawJson: JSON.stringify(parsed, null, 2),
      rawText: null,
      nonJsonNote: null,
    };
  } catch {
    return {
      source,
      entries: [],
      rawJson: null,
      rawText: rawText,
      nonJsonNote: "Attached content is plain text (not JSON).",
    };
  }
}

function formatPreviewValue(val: unknown): string {
  if (typeof val === "string") {
    const compact = val.replace(/\s+/g, " ").trim();
    const clipped = compact.length > 40 ? `${compact.slice(0, 39)}…` : compact;
    return `"${clipped}"`;
  }
  if (typeof val === "number" || typeof val === "boolean" || val === null) {
    return String(val);
  }
  if (Array.isArray(val)) {
    const joined = val
      .slice(0, 3)
      .map((x) => (typeof x === "string" ? x : JSON.stringify(x)))
      .join(" ");
    const suffix = val.length > 3 ? " …" : "";
    const clipped = joined.length > 36 ? `${joined.slice(0, 35)}…` : joined;
    return `[${clipped}${suffix}]`;
  }
  const json = JSON.stringify(val);
  return json.length > 36 ? `${json.slice(0, 35)}…` : json;
}

/**
 * Formats a concise one-line argument preview for the Evidence table
 * (e.g. `script="solve_fractions.py", mode="socratic"`).
 */
export function formatToolArgsPreview(
  parsed: ParsedToolArgs,
  omitProgramName?: string | null,
  maxChars = 84,
): string | null {
  if (parsed.entries.length === 0) return null;

  // Avoid repeating `program="python3"` when the tool column already says `python3`
  // and there are other informative entries.
  const filtered =
    omitProgramName && parsed.entries.length > 1
      ? parsed.entries.filter(
          (e) => !(e.key === "program" && e.value === omitProgramName),
        )
      : parsed.entries;

  const list = filtered.length > 0 ? filtered : parsed.entries;
  const parts: string[] = [];
  for (const entry of list.slice(0, 4)) {
    parts.push(`${entry.key}=${formatPreviewValue(entry.value)}`);
  }
  const joined = parts.join(", ");
  if (joined.length <= maxChars) return joined;
  return `${joined.slice(0, maxChars - 1)}…`;
}

/**
 * Convenience helper for the Evidence table: extracts inline ToolCall args/details
 * and returns a one-line preview string (or null for non-ToolCall records).
 */
export function toolCallPreviewOf(
  kind: string,
  payload: EvidenceEnvelopePayload | null,
  targetName?: string | null,
): string | null {
  const short = kind.includes("/") ? kind.slice(kind.lastIndexOf("/") + 1) : kind;
  if (short !== "ToolCall") return null;
  const parsed = extractInlineToolArgs(payload);
  return formatToolArgsPreview(parsed, targetName);
}

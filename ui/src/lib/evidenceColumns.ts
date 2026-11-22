// Evidence Table column definitions, ordering, visibility, widths, and
// localStorage persistence for the Provenance v2 Dashboard.

export type EvidenceColumnId =
  | "captured"
  | "kind"
  | "policy"
  | "target"
  | "actor"
  | "session"
  | "ref"
  | "streamSeq";

export interface EvidenceColumnDef {
  id: EvidenceColumnId;
  label: string;
  defaultWidth: number;
  minWidth: number;
  defaultVisible: boolean;
}

export const EVIDENCE_COLUMNS: ReadonlyArray<EvidenceColumnDef> = [
  { id: "captured", label: "Captured", defaultWidth: 156, minWidth: 120, defaultVisible: true },
  { id: "kind", label: "Kind", defaultWidth: 132, minWidth: 100, defaultVisible: true },
  { id: "policy", label: "Policy", defaultWidth: 82, minWidth: 72, defaultVisible: true },
  { id: "target", label: "Target / Tool", defaultWidth: 210, minWidth: 140, defaultVisible: true },
  { id: "actor", label: "Actor", defaultWidth: 165, minWidth: 110, defaultVisible: true },
  { id: "session", label: "Session", defaultWidth: 200, minWidth: 120, defaultVisible: false },
  { id: "ref", label: "Record Ref", defaultWidth: 165, minWidth: 130, defaultVisible: true },
  { id: "streamSeq", label: "Stream / Seq", defaultWidth: 180, minWidth: 120, defaultVisible: false },
];

export const COLUMN_DEF_BY_ID: Record<EvidenceColumnId, EvidenceColumnDef> =
  Object.fromEntries(EVIDENCE_COLUMNS.map((c) => [c.id, c])) as Record<
    EvidenceColumnId,
    EvidenceColumnDef
  >;

export interface EvidenceColumnPrefs {
  order: EvidenceColumnId[];
  visible: Record<EvidenceColumnId, boolean>;
  widths: Record<EvidenceColumnId, number>;
}

export const EVIDENCE_COLUMNS_STORAGE_KEY = "r5e.v2.evidence.columns.v1";

export function defaultColumnPrefs(): EvidenceColumnPrefs {
  const order = EVIDENCE_COLUMNS.map((c) => c.id);
  const visible = Object.fromEntries(
    EVIDENCE_COLUMNS.map((c) => [c.id, c.defaultVisible]),
  ) as Record<EvidenceColumnId, boolean>;
  const widths = Object.fromEntries(
    EVIDENCE_COLUMNS.map((c) => [c.id, c.defaultWidth]),
  ) as Record<EvidenceColumnId, number>;
  return { order, visible, widths };
}

export function loadColumnPrefs(): EvidenceColumnPrefs {
  const defaults = defaultColumnPrefs();
  if (typeof window === "undefined") return defaults;
  try {
    const raw = window.localStorage?.getItem(EVIDENCE_COLUMNS_STORAGE_KEY);
    if (!raw) return defaults;
    const parsed = JSON.parse(raw) as Partial<EvidenceColumnPrefs>;
    const validIds = new Set<string>(EVIDENCE_COLUMNS.map((c) => c.id));
    const order: EvidenceColumnId[] = [];
    if (Array.isArray(parsed.order)) {
      for (const id of parsed.order) {
        if (validIds.has(id) && !order.includes(id)) {
          order.push(id);
        }
      }
    }
    for (const c of EVIDENCE_COLUMNS) {
      if (!order.includes(c.id)) order.push(c.id);
    }

    const visible = { ...defaults.visible };
    if (parsed.visible && typeof parsed.visible === "object") {
      for (const c of EVIDENCE_COLUMNS) {
        if (typeof parsed.visible[c.id] === "boolean") {
          visible[c.id] = parsed.visible[c.id];
        }
      }
    }

    const widths = { ...defaults.widths };
    if (parsed.widths && typeof parsed.widths === "object") {
      for (const c of EVIDENCE_COLUMNS) {
        const w = parsed.widths[c.id];
        if (typeof w === "number" && Number.isFinite(w)) {
          widths[c.id] = Math.max(c.minWidth, Math.min(800, Math.round(w)));
        }
      }
    }

    return { order, visible, widths };
  } catch {
    return defaults;
  }
}

export function saveColumnPrefs(prefs: EvidenceColumnPrefs): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage?.setItem(EVIDENCE_COLUMNS_STORAGE_KEY, JSON.stringify(prefs));
  } catch {
    // Ignore storage quota / private mode failures
  }
}

export function reorderColumnIds(
  order: readonly EvidenceColumnId[],
  fromId: EvidenceColumnId,
  toId: EvidenceColumnId,
): EvidenceColumnId[] {
  if (fromId === toId) return order.slice();
  const next = order.slice();
  const fromIdx = next.indexOf(fromId);
  const toIdx = next.indexOf(toId);
  if (fromIdx < 0 || toIdx < 0) return next;
  const [moved] = next.splice(fromIdx, 1);
  if (moved) next.splice(toIdx, 0, moved);
  return next;
}

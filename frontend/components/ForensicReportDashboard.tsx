"use client";

import {
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

/* ======================================================
   TYPES
====================================================== */

type ReportCase = {
  id: number;
  case_code: string;
  name: string;
  case_type: string;
  description: string;
  investigator: string;
  status: string;
  created_at: string | null;
  updated_at: string | null;
};

type RiskEvidenceItem = {
  evidence_id: number;
  evidence_code: string;
  filename: string;
  risk_score: number;
  risk_level: string;
};

type BlindSpotSummaryItem = {
  evidence_id: number;
  evidence_code: string;
  filename: string;
  forensic_risk: number;
  coverage_score: number;
  blind_spot_score: number;
  severity: string;
};

type ExecutiveSummary = {
  total_evidence: number;
  analyzed_evidence: number;
  untriaged_evidence: number;
  high_risk_evidence: number;
  suspicious_evidence: number;
  low_risk_evidence: number;
  integrity_failures: number;
  average_coverage: number;
  high_blind_spots: number;
  medium_blind_spots: number;
  correlation_relationships: number;
  strong_correlations: number;
  correlation_clusters: number;
  timeline_events: number;
  chain_of_custody_entries: number;
  top_risk_evidence: RiskEvidenceItem[];
  top_blind_spots: BlindSpotSummaryItem[];
};

type EvidenceReportItem = {
  evidence_id: number;
  evidence_code: string;
  filename: string;
  file_extension: string;
  mime_type: string;
  file_size: number;
  entropy: number;
  status: string;
  uploaded_at: string | null;
  integrity: {
    status: string;
    verified_at: string | null;
    sha256: string;
    sha1: string;
    md5: string;
  };
  triage:
    | {
        analyzer: string;
        analysis_method: string;
        risk_score: number;
        risk_level: string;
        predicted_class: string | null;
        model_name: string | null;
        benign_probability: number | null;
        malicious_probability: number | null;
        findings: Array<Record<string, unknown>>;
        indicators: Array<Record<string, unknown>>;
        limitations: string;
        created_at: string | null;
      }
    | null;
  coverage:
    | {
        coverage_score: number;
        coverage_level: string;
      }
    | null;
  blind_spot:
    | {
        blind_spot_score: number;
        severity: string;
        reasons: string[];
      }
    | null;
  relationships: Array<{
    related_evidence_id: number;
    related_evidence_code: string;
    related_filename: string;
    relation_type: string;
    strength: number;
    level: string;
    indicator_type: string | null;
    indicator_value: string | null;
    reason: string;
  }>;
};

type CorrelationRelationship = {
  relation_type: string;
  strength: number;
  level: string;
  source_evidence_code: string;
  source_filename: string;
  target_evidence_code: string;
  target_filename: string;
  indicator_type: string | null;
  indicator_value: string | null;
  reason: string;
};

type ReportResponse = {
  report_version: string;
  report_type: string;
  generated_at: string;
  case: ReportCase;
  executive_summary: ExecutiveSummary;
  evidence: EvidenceReportItem[];
  coverage: {
    formula: string;
    summary: Record<string, number>;
    disclaimer: string;
  };
  blind_spots: {
    formula: string;
    coverage_formula: string;
    summary: Record<string, number>;
    disclaimer: string;
  };
  correlations: {
    summary: {
      total_nodes?: number;
      total_edges?: number;
      correlated_evidence?: number;
      correlation_links?: number;
      strong_correlations?: number;
      medium_correlations?: number;
      clusters?: number;
    };
    relationships: CorrelationRelationship[];
    clusters: Array<Record<string, unknown>>;
    disclaimer: string;
  };
  timeline: {
    summary: {
      total_events?: number;
      evidence_touched?: number;
      category_counts?: Record<string, number>;
      severity_counts?: Record<string, number>;
    };
    disclaimer: string;
  };
  chain_of_custody: {
    total_entries: number;
    event_counts: Record<string, number>;
    note: string;
  };
  methodology: string[];
  limitations: string[];
  export: {
    json_ready: boolean;
    pdf_ready: boolean;
    pdf_phase: string;
    pdf_method?: string;
    pdf_endpoint?: string;
  };
};

type Props = {
  caseId: number;
  onOpenEvidence: (evidenceId: number) => void;
  onOpenGraph?: () => void;
};

type ExportResult = {
  sha256: string;
  serverSha256: string | null;
  matched: boolean | null;
  size: number;
  version: string | null;
  filename: string;
};

/* ======================================================
   API
====================================================== */

const API_URL =
  process.env.NEXT_PUBLIC_API_URL ??
  "http://127.0.0.1:8000";

async function getErrorMessage(response: Response) {
  try {
    const body = await response.json();

    if (typeof body?.detail === "string") {
      return body.detail;
    }

    return JSON.stringify(body?.detail ?? body);
  } catch {
    return `Request failed with status ${response.status}`;
  }
}

async function getReport(caseId: number): Promise<ReportResponse> {
  const response = await fetch(`${API_URL}/api/report/cases/${caseId}`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(await getErrorMessage(response));
  }

  return response.json();
}

/* ======================================================
   HELPERS
====================================================== */

function clamp(value: number) {
  return Math.max(0, Math.min(value, 100));
}

function percent(numerator: number, denominator: number) {
  if (denominator <= 0) {
    return 0;
  }

  return clamp((numerator / denominator) * 100);
}

function formatNumber(value: number) {
  if (!Number.isFinite(value)) {
    return "0";
  }

  return Number.isInteger(value) ? String(value) : value.toFixed(1);
}

function formatBytes(bytes: number) {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return "0 B";
  }

  const units = ["B", "KB", "MB", "GB"];
  let value = bytes;
  let index = 0;

  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }

  return `${value.toFixed(index === 0 ? 0 : 2)} ${units[index]}`;
}

function formatDate(value: string | null) {
  if (!value) {
    return "—";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function readableName(value: string) {
  return value.replace(/_/g, " ");
}

function safeFilenamePart(value: string) {
  return (
    value
      .trim()
      .replace(/[^A-Za-z0-9._-]+/g, "_")
      .replace(/^[_\-.]+|[_\-.]+$/g, "") || "case"
  );
}

function riskColor(level: string | null) {
  if (level === "HIGH RISK") return "#ff7474";
  if (level === "SUSPICIOUS") return "#ffba68";
  if (level === "LOW RISK") return "#70e5b5";
  return "#8091a3";
}

function blindSpotColor(severity: string | null) {
  if (severity === "HIGH") return "#ff7474";
  if (severity === "MEDIUM") return "#ffba68";
  return "#70e5b5";
}

function coverageColor(score: number) {
  if (score >= 75) return "#70e5b5";
  if (score >= 50) return "#7fc6ff";
  if (score >= 25) return "#ffba68";
  return "#ff7474";
}

async function sha256Hex(bytes: ArrayBuffer) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);

  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

/* ======================================================
   SMALL VISUALS
====================================================== */

function DonutGauge(props: {
  label: string;
  value: number;
  detail: string;
  color: string;
}) {
  const value = clamp(props.value);
  const radius = 43;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference - (value / 100) * circumference;

  return (
    <article
      style={{
        border: "1px solid var(--border)",
        borderRadius: "16px",
        background: "var(--panel)",
        padding: "16px",
        minWidth: 0,
        overflow: "hidden",
      }}
    >
      <div style={{ display: "grid", placeItems: "center" }}>
        <div style={{ position: "relative", width: "112px", height: "112px" }}>
          <svg width="112" height="112" viewBox="0 0 112 112" aria-hidden="true">
            <circle
              cx="56"
              cy="56"
              r={radius}
              fill="none"
              stroke="rgba(255,255,255,0.07)"
              strokeWidth="9"
            />
            <circle
              cx="56"
              cy="56"
              r={radius}
              fill="none"
              stroke={props.color}
              strokeWidth="9"
              strokeLinecap="round"
              strokeDasharray={circumference}
              strokeDashoffset={dashOffset}
              transform="rotate(-90 56 56)"
            />
          </svg>

          <div
            style={{
              position: "absolute",
              inset: 0,
              display: "grid",
              placeItems: "center",
            }}
          >
            <strong style={{ fontSize: "22px", color: props.color }}>
              {formatNumber(value)}%
            </strong>
          </div>
        </div>
      </div>

      <strong
        style={{
          display: "block",
          textAlign: "center",
          marginTop: "8px",
          fontSize: "12px",
          overflowWrap: "anywhere",
        }}
      >
        {props.label}
      </strong>

      <span
        style={{
          display: "block",
          textAlign: "center",
          marginTop: "4px",
          fontSize: "10px",
          opacity: 0.6,
          lineHeight: 1.4,
          overflowWrap: "anywhere",
        }}
      >
        {props.detail}
      </span>
    </article>
  );
}

function HorizontalBar(props: {
  label: string;
  value: number;
  max: number;
  color: string;
  detail?: string;
}) {
  const width =
    props.max > 0 ? clamp((props.value / props.max) * 100) : 0;

  return (
    <div style={{ marginTop: "11px", minWidth: 0 }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-start",
          gap: "12px",
          fontSize: "11px",
          minWidth: 0,
        }}
      >
        <span
          style={{
            minWidth: 0,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            flex: "1 1 auto",
          }}
          title={props.label}
        >
          {props.label}
        </span>

        <strong
          style={{
            color: props.color,
            flexShrink: 0,
            minWidth: "36px",
            textAlign: "right",
          }}
        >
          {formatNumber(props.value)}
        </strong>
      </div>

      {props.detail && (
        <span
          style={{
            display: "block",
            marginTop: "2px",
            fontSize: "9px",
            opacity: 0.5,
            overflowWrap: "anywhere",
          }}
        >
          {props.detail}
        </span>
      )}

      <div
        style={{
          height: "8px",
          borderRadius: "999px",
          background: "rgba(255,255,255,0.065)",
          overflow: "hidden",
          marginTop: "6px",
        }}
      >
        <div
          style={{
            width: `${width}%`,
            height: "100%",
            borderRadius: "999px",
            background: props.color,
            transition: "width 220ms ease",
          }}
        />
      </div>
    </div>
  );
}

function ReportPanel(props: {
  eyebrow: string;
  title: string;
  children: ReactNode;
}) {
  return (
    <section
      style={{
        border: "1px solid var(--border)",
        borderRadius: "18px",
        background: "var(--panel)",
        padding: "18px",
        minWidth: 0,
        width: "100%",
        overflow: "hidden",
      }}
    >
      <span className="eyebrow">{props.eyebrow}</span>
      <h2 style={{ marginTop: "5px" }}>{props.title}</h2>
      <div style={{ marginTop: "16px", minWidth: 0 }}>{props.children}</div>
    </section>
  );
}

function StatCard(props: {
  label: string;
  value: number;
  color: string;
}) {
  return (
    <article
      style={{
        border: "1px solid var(--border)",
        borderRadius: "16px",
        background: "var(--panel)",
        padding: "16px 18px",
        minWidth: 0,
      }}
    >
      <span className="eyebrow">{props.label}</span>
      <strong
        style={{
          display: "block",
          marginTop: "10px",
          fontSize: "28px",
          color: props.color,
        }}
      >
        {props.value}
      </strong>
    </article>
  );
}

function MetricMini(props: {
  label: string;
  value: string;
  color?: string;
}) {
  return (
    <div style={{ minWidth: 0 }}>
      <span
        className="eyebrow"
        style={{
          display: "block",
          whiteSpace: "nowrap",
          overflow: "hidden",
          textOverflow: "ellipsis",
        }}
      >
        {props.label}
      </span>
      <strong
        style={{
          display: "block",
          marginTop: "4px",
          fontSize: "14px",
          color: props.color ?? "inherit",
        }}
      >
        {props.value}
      </strong>
    </div>
  );
}

/* ======================================================
   MAIN COMPONENT
====================================================== */

export default function ForensicReportDashboard({
  caseId,
  onOpenEvidence,
  onOpenGraph,
}: Props) {
  const [report, setReport] = useState<ReportResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState("");
  const [exportResult, setExportResult] = useState<ExportResult | null>(null);

  async function loadReport() {
    setLoading(true);
    setError("");

    try {
      setReport(await getReport(caseId));
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "Unable to load forensic report."
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadReport();
  }, [caseId]);

  const visuals = useMemo(() => {
    if (!report) {
      return null;
    }

    const summary = report.executive_summary;
    const total = Math.max(summary.total_evidence, 0);
    const integrityVerified = report.evidence.filter(
      (item) => item.integrity.status.toUpperCase() === "VERIFIED"
    ).length;
    const correlatedEvidence =
      report.correlations.summary.correlated_evidence ?? 0;

    return {
      analysisCompletion: percent(summary.analyzed_evidence, total),
      averageCoverage: clamp(summary.average_coverage),
      integrityCoverage: percent(integrityVerified, total),
      highBlindSpotRatio: percent(summary.high_blind_spots, total),
      correlationCoverage: percent(correlatedEvidence, total),
      integrityVerified,
    };
  }, [report]);

  async function downloadPdf() {
    if (!report || exporting) {
      return;
    }

    setExporting(true);
    setError("");

    try {
      const response = await fetch(`${API_URL}/api/report/cases/${caseId}/pdf`, {
        method: "POST",
      });

      if (!response.ok) {
        throw new Error(await getErrorMessage(response));
      }

      const bytes = await response.arrayBuffer();
      const clientSha256 = await sha256Hex(bytes);
      const serverSha256 = response.headers.get("X-SYNAPSE-Report-SHA256");
      const version = response.headers.get("X-SYNAPSE-Report-Version");

      const fallbackFilename =
        "SYNAPSE_" +
        safeFilenamePart(report.case.case_code) +
        "_" +
        safeFilenamePart(report.case.name) +
        "_Forensic_Report.pdf";

      const disposition = response.headers.get("Content-Disposition");
      const match = disposition?.match(/filename="?([^";]+)"?/i);
      const filename = match?.[1] ?? fallbackFilename;

      const blob = new Blob([bytes], { type: "application/pdf" });
      const objectUrl = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = objectUrl;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(objectUrl);

      const matched = serverSha256
        ? serverSha256.toLowerCase() === clientSha256
        : null;

      setExportResult({
        sha256: clientSha256,
        serverSha256,
        matched,
        size: bytes.byteLength,
        version,
        filename,
      });

      await loadReport();
    } catch (error) {
      setError(error instanceof Error ? error.message : "PDF generation failed.");
    } finally {
      setExporting(false);
    }
  }

  if (loading) {
    return (
      <div className="centerScreen" style={{ minHeight: "440px" }}>
        Building forensic report...
      </div>
    );
  }

  if (error && !report) {
    return (
      <div className="formError">
        {error}
        <button
          type="button"
          onClick={() => void loadReport()}
          style={{ marginLeft: "12px" }}
        >
          Retry
        </button>
      </div>
    );
  }

  if (!report || !visuals) {
    return <div className="emptyState">Report unavailable.</div>;
  }

  const summary = report.executive_summary;
  const highestRisk = Math.max(
    100,
    ...summary.top_risk_evidence.map((item) => item.risk_score)
  );
  const strongestCorrelation = Math.max(
    100,
    ...report.correlations.relationships.map((item) => item.strength)
  );
  const timelineCategories = Object.entries(
    report.timeline.summary.category_counts ?? {}
  );
  const maxTimelineCount = Math.max(
    1,
    ...timelineCategories.map(([, value]) => value)
  );
  const ledgerEvents = Object.entries(
    report.chain_of_custody.event_counts ?? {}
  )
    .sort((first, second) => second[1] - first[1])
    .slice(0, 8);
  const maxLedgerCount = Math.max(1, ...ledgerEvents.map(([, value]) => value));

  return (
    <section
      style={{
        width: "100%",
        minWidth: 0,
        maxWidth: "100%",
        overflowX: "clip",
      }}
    >
      {error && (
        <div className="formError" style={{ marginBottom: "16px" }}>
          {error}
        </div>
      )}

      {/* HERO */}
      <section
        style={{
          border: "1px solid var(--border)",
          borderRadius: "20px",
          background:
            "linear-gradient(135deg, rgba(76,168,232,0.10), rgba(9,19,30,0.96) 42%, rgba(131,102,199,0.08))",
          padding: "22px",
          display: "flex",
          justifyContent: "space-between",
          gap: "24px",
          alignItems: "center",
          flexWrap: "wrap",
          minWidth: 0,
        }}
      >
        <div style={{ minWidth: 0, flex: "1 1 520px" }}>
          <span className="eyebrow">SYNAPSE FORENSIC REPORT</span>
          <h1 style={{ marginTop: "7px", overflowWrap: "anywhere" }}>
            {report.case.name}
          </h1>
          <p
            style={{
              marginTop: "7px",
              opacity: 0.7,
              maxWidth: "720px",
              lineHeight: 1.6,
              overflowWrap: "anywhere",
            }}
          >
            {report.case.description || "Digital forensic investigation report."}
          </p>

          <div
            style={{
              display: "flex",
              gap: "8px",
              flexWrap: "wrap",
              marginTop: "13px",
            }}
          >
            <span className="artifactCode">{report.case.case_code}</span>
            <span className="artifactCode">{report.case.investigator}</span>
            <span className="artifactCode" style={{ color: "#70e5b5" }}>
              {report.case.status}
            </span>
          </div>
        </div>

        <div
          style={{
            display: "flex",
            gap: "9px",
            flexWrap: "wrap",
            flex: "0 0 auto",
          }}
        >
          <button type="button" onClick={() => void loadReport()} disabled={exporting}>
            Refresh
          </button>
          <button
            type="button"
            onClick={() => void downloadPdf()}
            disabled={exporting || !report.export.pdf_ready}
            style={{
              borderColor: "rgba(112,229,181,0.45)",
              color: "#9cf2ce",
            }}
          >
            {exporting ? "Generating PDF..." : "Generate & Download PDF"}
          </button>
        </div>
      </section>

      {/* VISUAL GAUGES */}
      <section
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))",
          gap: "12px",
          marginTop: "18px",
          width: "100%",
          minWidth: 0,
        }}
      >
        <DonutGauge
          label="Analysis Complete"
          value={visuals.analysisCompletion}
          detail={`${summary.analyzed_evidence} of ${summary.total_evidence} artifacts`}
          color="#e993ff"
        />
        <DonutGauge
          label="Average Coverage"
          value={visuals.averageCoverage}
          detail="Observable investigation coverage"
          color={coverageColor(visuals.averageCoverage)}
        />
        <DonutGauge
          label="Integrity Verified"
          value={visuals.integrityCoverage}
          detail={`${visuals.integrityVerified} verified artifacts`}
          color="#70e5b5"
        />
        <DonutGauge
          label="High Blind Spots"
          value={visuals.highBlindSpotRatio}
          detail={`${summary.high_blind_spots} high-priority review gaps`}
          color={summary.high_blind_spots > 0 ? "#ff7474" : "#70e5b5"}
        />
        <DonutGauge
          label="Correlation Coverage"
          value={visuals.correlationCoverage}
          detail="Evidence participating in correlations"
          color="#a58cff"
        />
      </section>

      {/* RISK COUNTS */}
      <section
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
          gap: "12px",
          marginTop: "18px",
          minWidth: 0,
        }}
      >
        <StatCard label="HIGH RISK" value={summary.high_risk_evidence} color="#ff7474" />
        <StatCard label="SUSPICIOUS" value={summary.suspicious_evidence} color="#ffba68" />
        <StatCard label="LOW RISK" value={summary.low_risk_evidence} color="#70e5b5" />
        <StatCard label="UNTRIAGED" value={summary.untriaged_evidence} color="#9aa9ba" />
      </section>

      {/* RISK + CORRELATION */}
      <section
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(360px, 1fr))",
          gap: "18px",
          marginTop: "18px",
          minWidth: 0,
          alignItems: "stretch",
        }}
      >
        <ReportPanel eyebrow="FORENSIC RISK" title="Highest-Risk Evidence">
          {summary.top_risk_evidence.length === 0 ? (
            <div className="emptyState">No completed forensic triage yet.</div>
          ) : (
            summary.top_risk_evidence.slice(0, 6).map((item) => (
              <button
                type="button"
                key={item.evidence_id}
                onClick={() => onOpenEvidence(item.evidence_id)}
                style={{
                  display: "block",
                  width: "100%",
                  minWidth: 0,
                  textAlign: "left",
                  background: "transparent",
                  border: "none",
                  padding: 0,
                  margin: 0,
                }}
              >
                <HorizontalBar
                  label={`${item.evidence_code} · ${item.filename}`}
                  value={item.risk_score}
                  max={highestRisk}
                  detail={item.risk_level}
                  color={riskColor(item.risk_level)}
                />
              </button>
            ))
          )}
        </ReportPanel>

        <ReportPanel eyebrow="CORRELATION INTELLIGENCE" title="Strongest Relationships">
          {report.correlations.relationships.length === 0 ? (
            <div
              className="emptyState"
              style={{
                minHeight: "150px",
                display: "grid",
                placeItems: "center",
                textAlign: "center",
              }}
            >
              No deterministic cross-evidence relationships.
            </div>
          ) : (
            report.correlations.relationships.slice(0, 6).map((relation, index) => (
              <HorizontalBar
                key={`${relation.source_evidence_code}-${relation.target_evidence_code}-${index}`}
                label={`${relation.source_evidence_code} ↔ ${relation.target_evidence_code}`}
                value={relation.strength}
                max={strongestCorrelation}
                detail={readableName(relation.relation_type)}
                color="#a58cff"
              />
            ))
          )}

          {onOpenGraph && report.correlations.relationships.length > 0 && (
            <button type="button" onClick={onOpenGraph} style={{ marginTop: "16px", width: "100%" }}>
              Open Evidence Graph
            </button>
          )}
        </ReportPanel>
      </section>

      {/* BLIND SPOTS */}
      <section style={{ marginTop: "18px", minWidth: 0 }}>
        <ReportPanel eyebrow="HUMAN-AWARE FORENSICS" title="Priority Blind Spots">
          {summary.top_blind_spots.length === 0 ? (
            <div className="emptyState">
              No risk-aware Blind Spot items are currently available.
            </div>
          ) : (
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))",
                gap: "12px",
                width: "100%",
                minWidth: 0,
              }}
            >
              {summary.top_blind_spots.slice(0, 6).map((item) => (
                <button
                  type="button"
                  key={item.evidence_id}
                  onClick={() => onOpenEvidence(item.evidence_id)}
                  style={{
                    display: "block",
                    width: "100%",
                    minWidth: 0,
                    maxWidth: "100%",
                    textAlign: "left",
                    padding: "14px",
                    border: `1px solid ${blindSpotColor(item.severity)}44`,
                    borderRadius: "13px",
                    background: "rgba(255,255,255,0.025)",
                    overflow: "hidden",
                  }}
                >
                  <div style={{ minWidth: 0 }}>
                    <span
                      className="eyebrow"
                      style={{
                        display: "block",
                        color: blindSpotColor(item.severity),
                        overflowWrap: "anywhere",
                      }}
                    >
                      {item.severity} BLIND SPOT
                    </span>

                    <div
                      style={{
                        display: "flex",
                        alignItems: "baseline",
                        gap: "7px",
                        marginTop: "7px",
                        minWidth: 0,
                      }}
                    >
                      <strong style={{ flexShrink: 0 }}>{item.evidence_code}</strong>
                      <span
                        style={{
                          minWidth: 0,
                          fontSize: "11px",
                          opacity: 0.62,
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                        }}
                        title={item.filename}
                      >
                        {item.filename}
                      </span>
                    </div>
                  </div>

                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "repeat(3, minmax(0, 1fr))",
                      gap: "10px",
                      marginTop: "14px",
                      paddingTop: "12px",
                      borderTop: "1px solid rgba(255,255,255,0.06)",
                      minWidth: 0,
                    }}
                  >
                    <MetricMini
                      label="RISK"
                      value={`${formatNumber(item.forensic_risk)}%`}
                      color={riskColor(
                        item.forensic_risk >= 70
                          ? "HIGH RISK"
                          : item.forensic_risk >= 35
                            ? "SUSPICIOUS"
                            : "LOW RISK"
                      )}
                    />
                    <MetricMini
                      label="COVERAGE"
                      value={`${formatNumber(item.coverage_score)}%`}
                      color={coverageColor(item.coverage_score)}
                    />
                    <MetricMini
                      label="BLIND"
                      value={`${formatNumber(item.blind_spot_score)}%`}
                      color={blindSpotColor(item.severity)}
                    />
                  </div>
                </button>
              ))}
            </div>
          )}
        </ReportPanel>
      </section>

      {/* EVIDENCE TABLE */}
      <section style={{ marginTop: "18px", minWidth: 0 }}>
        <ReportPanel eyebrow="REPORT INVENTORY" title="Evidence Summary">
          <div
            style={{
              width: "100%",
              maxWidth: "100%",
              overflowX: "auto",
              overflowY: "hidden",
              borderRadius: "12px",
            }}
          >
            <table
              style={{
                width: "100%",
                borderCollapse: "collapse",
                minWidth: "920px",
                tableLayout: "fixed",
              }}
            >
              <colgroup>
                <col style={{ width: "150px" }} />
                <col style={{ width: "320px" }} />
                <col style={{ width: "90px" }} />
                <col style={{ width: "110px" }} />
                <col style={{ width: "90px" }} />
                <col style={{ width: "100px" }} />
                <col style={{ width: "100px" }} />
                <col style={{ width: "90px" }} />
              </colgroup>
              <thead>
                <tr>
                  {["Evidence", "Filename", "Type", "Integrity", "Risk", "Coverage", "Blind Spot", "Relations"].map(
                    (label) => (
                      <th
                        key={label}
                        style={{
                          textAlign: "left",
                          padding: "10px",
                          borderBottom: "1px solid var(--border)",
                          fontSize: "9px",
                          letterSpacing: "0.08em",
                          opacity: 0.6,
                        }}
                      >
                        {label}
                      </th>
                    )
                  )}
                </tr>
              </thead>
              <tbody>
                {report.evidence.map((item) => {
                  const risk = item.triage?.risk_score;
                  const level = item.triage?.risk_level ?? null;

                  return (
                    <tr key={item.evidence_id}>
                      <td style={{ padding: "11px", borderBottom: "1px solid var(--border)" }}>
                        <button type="button" onClick={() => onOpenEvidence(item.evidence_id)}>
                          {item.evidence_code}
                        </button>
                      </td>
                      <td
                        style={{
                          padding: "11px",
                          borderBottom: "1px solid var(--border)",
                          fontSize: "11px",
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                        }}
                        title={item.filename}
                      >
                        {item.filename}
                      </td>
                      <td style={{ padding: "11px", borderBottom: "1px solid var(--border)", fontSize: "11px" }}>
                        {item.file_extension || "none"}
                      </td>
                      <td
                        style={{
                          padding: "11px",
                          borderBottom: "1px solid var(--border)",
                          fontSize: "11px",
                          color:
                            item.integrity.status.toUpperCase() === "VERIFIED"
                              ? "#70e5b5"
                              : item.integrity.status.toUpperCase().includes("FAIL")
                                ? "#ff7474"
                                : "#9aa9ba",
                        }}
                      >
                        {item.integrity.status}
                      </td>
                      <td
                        style={{
                          padding: "11px",
                          borderBottom: "1px solid var(--border)",
                          fontWeight: 700,
                          color: riskColor(level),
                        }}
                      >
                        {risk !== undefined && risk !== null ? `${formatNumber(risk)}%` : "—"}
                      </td>
                      <td
                        style={{
                          padding: "11px",
                          borderBottom: "1px solid var(--border)",
                          color: item.coverage ? coverageColor(item.coverage.coverage_score) : "#9aa9ba",
                          fontWeight: 700,
                        }}
                      >
                        {item.coverage ? `${formatNumber(item.coverage.coverage_score)}%` : "—"}
                      </td>
                      <td
                        style={{
                          padding: "11px",
                          borderBottom: "1px solid var(--border)",
                          color: item.blind_spot ? blindSpotColor(item.blind_spot.severity) : "#9aa9ba",
                          fontWeight: 700,
                        }}
                      >
                        {item.blind_spot ? `${formatNumber(item.blind_spot.blind_spot_score)}%` : "—"}
                      </td>
                      <td style={{ padding: "11px", borderBottom: "1px solid var(--border)", fontSize: "11px" }}>
                        {item.relationships.length}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </ReportPanel>
      </section>

      {/* TIMELINE + LEDGER */}
      <section
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(360px, 1fr))",
          gap: "18px",
          marginTop: "18px",
          minWidth: 0,
          alignItems: "stretch",
        }}
      >
        <ReportPanel eyebrow="INVESTIGATION HISTORY" title="Timeline Event Distribution">
          {timelineCategories.length === 0 ? (
            <div className="emptyState">No timeline events.</div>
          ) : (
            timelineCategories.map(([category, count]) => (
              <HorizontalBar
                key={category}
                label={category}
                value={count}
                max={maxTimelineCount}
                color="#7fc6ff"
              />
            ))
          )}
        </ReportPanel>

        <ReportPanel eyebrow="TAMPER-EVIDENT AUDIT" title="Chain-of-Custody Events">
          {ledgerEvents.length === 0 ? (
            <div className="emptyState">No chain-of-custody entries.</div>
          ) : (
            ledgerEvents.map(([eventType, count]) => (
              <HorizontalBar
                key={eventType}
                label={readableName(eventType)}
                value={count}
                max={maxLedgerCount}
                color="#68e8d1"
              />
            ))
          )}
        </ReportPanel>
      </section>

      {/* EXPORT INTEGRITY */}
      <section style={{ marginTop: "18px", minWidth: 0 }}>
        <ReportPanel eyebrow="EXPORT INTEGRITY" title="Generated PDF Verification">
          {exportResult ? (
            <>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
                  gap: "10px",
                  minWidth: 0,
                }}
              >
                <div className="integrityCard">
                  <div>
                    <span className="eyebrow">PDF SIZE</span>
                    <strong>{formatBytes(exportResult.size)}</strong>
                  </div>
                </div>
                <div className="integrityCard">
                  <div>
                    <span className="eyebrow">REPORT VERSION</span>
                    <strong>{exportResult.version ?? report.report_version}</strong>
                  </div>
                </div>
                <div className="integrityCard">
                  <div>
                    <span className="eyebrow">HASH CHECK</span>
                    <strong style={{ color: exportResult.matched === false ? "#ff7474" : "#70e5b5" }}>
                      {exportResult.matched === false
                        ? "MISMATCH"
                        : exportResult.matched === true
                          ? "VERIFIED"
                          : "CLIENT VERIFIED"}
                    </strong>
                  </div>
                </div>
              </div>

              <div className="hashItem" style={{ marginTop: "12px", minWidth: 0 }}>
                <span>GENERATED PDF SHA-256</span>
                <code style={{ overflowWrap: "anywhere", wordBreak: "break-all" }}>
                  {exportResult.sha256}
                </code>
              </div>

              <div className="inspectorHint" style={{ marginTop: "10px", minWidth: 0 }}>
                <strong style={{ overflowWrap: "anywhere" }}>{exportResult.filename}</strong>
                <p style={{ marginTop: "5px", lineHeight: 1.5 }}>
                  The SHA-256 above was independently calculated in the browser from the exact PDF bytes that were downloaded.
                </p>
              </div>
            </>
          ) : (
            <div className="inspectorHint">
              <strong>No report exported in this browser session.</strong>
              <p style={{ marginTop: "5px", lineHeight: 1.6 }}>
                Generate the PDF to calculate and display its SHA-256 integrity fingerprint.
              </p>
            </div>
          )}
        </ReportPanel>
      </section>

      {/* METHODOLOGY + LIMITATIONS */}
      <section
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(360px, 1fr))",
          gap: "18px",
          marginTop: "18px",
          minWidth: 0,
          alignItems: "start",
        }}
      >
        <ReportPanel eyebrow="REPORT BASIS" title="Methodology">
          {report.methodology.map((item, index) => (
            <div
              className="inspectorHint"
              key={`${item}-${index}`}
              style={{ marginTop: index === 0 ? 0 : "8px", overflowWrap: "anywhere" }}
            >
              {item}
            </div>
          ))}
        </ReportPanel>

        <ReportPanel eyebrow="FORENSIC CAUTION" title="Limitations">
          {report.limitations.map((item, index) => (
            <div
              className="inspectorHint"
              key={`${item}-${index}`}
              style={{
                marginTop: index === 0 ? 0 : "8px",
                borderColor: "rgba(255,186,104,0.20)",
                overflowWrap: "anywhere",
              }}
            >
              {item}
            </div>
          ))}
        </ReportPanel>
      </section>

      <div
        className="inspectorHint"
        style={{
          marginTop: "18px",
          lineHeight: 1.6,
          overflowWrap: "anywhere",
        }}
      >
        <span className="eyebrow">REPORT STATE</span>
        <p style={{ marginTop: "6px" }}>
          Generated from the current deterministic SYNAPSE investigation state at{" "}
          <strong>{formatDate(report.generated_at)}</strong>. Risk values are investigation-prioritization signals and are not legal or maliciousness probabilities.
        </p>
      </div>
    </section>
  );
}

"use client";

import Link from "next/link";

import {
  ChangeEvent,
  FormEvent,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  useParams,
} from "next/navigation";

import AnalystCorrelationCards
  from "@/components/AnalystCorrelationCards";

import InvestigationTimeline
  from "@/components/InvestigationTimeline";

import ForensicReportDashboard
  from "@/components/ForensicReportDashboard";

import {
  askAnalyst,
  getAnalystBrief,
  getBlindSpots,
  getCase,
  getCaseArtifactTriage,
  getCaseAttention,
  getCaseCoverage,
  getCaseEvidence,
  getCaseLedger,
  getCasePredictions,
  getEvidenceGraph,
  getMLExplanation,
  rebuildEvidenceGraph,
  recalculateBlindSpots,
  recordEvidenceAttention,
  runArtifactTriage,
  runMLTriage,
  uploadEvidence,
  verifyEvidenceIntegrity,
} from "@/lib/api";

import type {
  AnalystAnswerResponse,
  AnalystBriefResponse,
  ArtifactTriageResult,
  BlindSpotItem,
  BlindSpotReport,
  CoverageReport,
  Evidence,
  EvidenceAttention,
  EvidenceCoverageItem,
  EvidenceGraph,
  ForensicCase,
  GraphCluster,
  GraphEdge,
  GraphNode,
  LedgerEntry,
  MLExplanation,
  MLPrediction,
} from "@/lib/types";


type WorkspaceTab =
  | "overview"
  | "evidence"
  | "graph"
  | "triage"
  | "analyst"
  | "blindspots"
  | "coverage"
  | "timeline"
  | "ledger"
  | "report";


type Point = {
  x: number;
  y: number;
};


type AnalystChatMessage = {
  id: string;

  role:
    | "user"
    | "assistant";

  text: string;

  response?: AnalystAnswerResponse;
};


/* ======================================================
   FORMATTERS
====================================================== */


function formatBytes(
  bytes: number
) {

  if (bytes === 0) {
    return "0 B";
  }


  const units = [
    "B",
    "KB",
    "MB",
    "GB",
  ];


  const index =
    Math.floor(
      Math.log(bytes)
      /
      Math.log(1024)
    );


  const value =
    bytes
    /
    Math.pow(
      1024,
      index
    );


  return `${value.toFixed(
    index === 0
      ? 0
      : 2
  )} ${units[index]}`;
}


function extensionOf(
  evidence: Evidence
) {

  return evidence
    .file_extension
    .toLowerCase();
}


function isPEFile(
  evidence: Evidence
) {

  const extension =
    extensionOf(
      evidence
    );


  return (
    extension === ".exe"
    ||
    extension === ".dll"
  );
}


function analyzerName(
  extension: string
) {

  const value =
    extension.toLowerCase();


  if (
    value === ".exe"
    ||
    value === ".dll"
  ) {
    return "PE MACHINE LEARNING";
  }


  if (
    value === ".pdf"
  ) {
    return "PDF STATIC ANALYSIS";
  }


  if (
    [
      ".txt",
      ".log",
      ".csv",
      ".json",
      ".xml",
      ".ini",
      ".cfg",
      ".conf",
      ".ps1",
      ".bat",
      ".cmd",
      ".vbs",
      ".js",
    ].includes(
      value
    )
  ) {
    return "TEXT + IOC ANALYSIS";
  }


  if (
    [
      ".png",
      ".jpg",
      ".jpeg",
    ].includes(
      value
    )
  ) {
    return "IMAGE FORENSICS";
  }


  if (
    [
      ".docx",
      ".xlsx",
      ".pptx",
    ].includes(
      value
    )
  ) {
    return "OFFICE PACKAGE ANALYSIS";
  }


  if (
    value === ".zip"
  ) {
    return "ARCHIVE ANALYSIS";
  }


  return "GENERIC METADATA";
}


function shortLabel(
  value: string,
  limit = 18
) {

  if (
    value.length <= limit
  ) {

    return value;
  }


  return `${value.slice(
    0,
    limit - 3
  )}...`;
}


/* ======================================================
   COLORS
====================================================== */


function getRiskColor(
  level: string | null
) {

  if (
    level === "HIGH RISK"
  ) {
    return "#ff7474";
  }


  if (
    level === "SUSPICIOUS"
  ) {
    return "#ffba68";
  }


  if (
    level === "LOW RISK"
  ) {
    return "#70e5b5";
  }


  return "#9aa9ba";
}


function getFindingColor(
  severity: string
) {

  if (
    severity === "HIGH"
  ) {
    return "#ff7474";
  }


  if (
    severity === "MEDIUM"
  ) {
    return "#ffba68";
  }


  if (
    severity === "LOW"
  ) {
    return "#70e5b5";
  }


  return "#9dd4ff";
}


function getSeverityColor(
  severity: string
) {

  if (
    severity === "HIGH"
  ) {
    return "#ff7474";
  }


  if (
    severity === "MEDIUM"
  ) {
    return "#ffba68";
  }


  return "#70e5b5";
}


function getCoverageColor(
  score: number
) {

  if (
    score >= 75
  ) {
    return "#70e5b5";
  }


  if (
    score >= 50
  ) {
    return "#7fc6ff";
  }


  if (
    score >= 25
  ) {
    return "#ffba68";
  }


  return "#ff7474";
}


function getNodeColor(
  node: GraphNode
) {

  if (
    node.type === "case"
  ) {
    return "#8ac7ff";
  }


  if (
    node.risk_level
    === "HIGH RISK"
  ) {
    return "#ff7474";
  }


  if (
    node.risk_level
    === "SUSPICIOUS"
  ) {
    return "#ffba68";
  }


  if (
    node.risk !== null
    &&
    node.risk !== undefined
  ) {
    return "#70e5b5";
  }


  return "#9aa9ba";
}


function getEdgeColor(
  type: GraphEdge["type"]
) {

  switch (type) {

    case "SAME_SHA256":
      return "#ff7474";

    case "SHARED_HASH":
      return "#e993ff";

    case "SHARED_IP":
      return "#ff996e";

    case "SHARED_DOMAIN":
      return "#a58cff";

    case "SHARED_URL":
      return "#6fb7ff";

    case "SHARED_EMAIL":
      return "#70e5b5";

    case "SHARED_INDICATOR":
      return "#f2cb70";

    case "SAME_FILENAME_DIFFERENT_HASH":
      return "#ffba68";

    default:
      return "#526474";
  }
}


/* ======================================================
   COVERAGE BAR
====================================================== */


function CoverageBar(
  props: {
    label: string;
    value: number;
    description: string;
  }
) {

  return (

    <div
      style={{
        marginTop:
          "14px",
      }}
    >

      <div
        style={{
          display:
            "flex",

          justifyContent:
            "space-between",

          gap:
            "12px",

          alignItems:
            "center",
        }}
      >

        <div>

          <strong
            style={{
              display:
                "block",

              fontSize:
                "13px",
            }}
          >
            {
              props.label
            }
          </strong>


          <span
            style={{
              fontSize:
                "11px",

              opacity:
                0.65,
            }}
          >
            {
              props.description
            }
          </span>

        </div>


        <strong
          style={{
            color:
              getCoverageColor(
                props.value
              ),
          }}
        >
          {
            props.value.toFixed(
              1
            )
          }%
        </strong>

      </div>


      <div
        style={{
          height:
            "7px",

          borderRadius:
            "999px",

          background:
            "rgba(255,255,255,0.07)",

          overflow:
            "hidden",

          marginTop:
            "8px",
        }}
      >

        <div
          style={{
            height:
              "100%",

            width:
              `${Math.max(
                0,
                Math.min(
                  props.value,
                  100
                )
              )}%`,

            background:
              getCoverageColor(
                props.value
              ),

            borderRadius:
              "999px",
          }}
        />

      </div>

    </div>
  );
}


/* ======================================================
   PAGE
====================================================== */


export default function CasePage() {

  const params =
    useParams<{
      id: string;
    }>();


  const caseId =
    Number(
      params.id
    );


  const fileInputRef =
    useRef<HTMLInputElement | null>(
      null
    );


  const [
    activeTab,
    setActiveTab,
  ] =
    useState<WorkspaceTab>(
      "overview"
    );


  const [
    forensicCase,
    setForensicCase,
  ] =
    useState<ForensicCase | null>(
      null
    );


  const [
    evidence,
    setEvidence,
  ] =
    useState<Evidence[]>(
      []
    );


  const [
    ledger,
    setLedger,
  ] =
    useState<LedgerEntry[]>(
      []
    );


  const [
    predictions,
    setPredictions,
  ] =
    useState<MLPrediction[]>(
      []
    );


  const [
    triageResults,
    setTriageResults,
  ] =
    useState<
      Record<
        number,
        ArtifactTriageResult
      >
    >({});


  const [
    attentionRecords,
    setAttentionRecords,
  ] =
    useState<
      Record<
        number,
        EvidenceAttention
      >
    >({});


  const [
    coverageReport,
    setCoverageReport,
  ] =
    useState<CoverageReport | null>(
      null
    );


  const [
    selectedCoverage,
    setSelectedCoverage,
  ] =
    useState<EvidenceCoverageItem | null>(
      null
    );


  const [
    blindSpotReport,
    setBlindSpotReport,
  ] =
    useState<BlindSpotReport | null>(
      null
    );


  const [
    selectedBlindSpot,
    setSelectedBlindSpot,
  ] =
    useState<BlindSpotItem | null>(
      null
    );


  const [
    blindSpotLoading,
    setBlindSpotLoading,
  ] =
    useState(false);


  const [
    analystBrief,
    setAnalystBrief,
  ] =
    useState<AnalystBriefResponse | null>(
      null
    );


  const [
    analystMessages,
    setAnalystMessages,
  ] =
    useState<AnalystChatMessage[]>(
      []
    );


  const [
    analystInput,
    setAnalystInput,
  ] =
    useState("");


  const [
    analystLoading,
    setAnalystLoading,
  ] =
    useState(false);


  const [
    graph,
    setGraph,
  ] =
    useState<EvidenceGraph | null>(
      null
    );


  const [
    selectedGraphNode,
    setSelectedGraphNode,
  ] =
    useState<GraphNode | null>(
      null
    );


  const [
    selectedGraphEdge,
    setSelectedGraphEdge,
  ] =
    useState<GraphEdge | null>(
      null
    );


  const [
    selectedGraphCluster,
    setSelectedGraphCluster,
  ] =
    useState<GraphCluster | null>(
      null
    );


  const [
    selectedEvidence,
    setSelectedEvidence,
  ] =
    useState<Evidence | null>(
      null
    );


  const [
    explanation,
    setExplanation,
  ] =
    useState<MLExplanation | null>(
      null
    );


  const [
    loading,
    setLoading,
  ] =
    useState(true);


  const [
    uploading,
    setUploading,
  ] =
    useState(false);


  const [
    graphLoading,
    setGraphLoading,
  ] =
    useState(false);


  const [
    verifyingId,
    setVerifyingId,
  ] =
    useState<number | null>(
      null
    );


  const [
    triagingId,
    setTriagingId,
  ] =
    useState<number | null>(
      null
    );


  const [
    explainingId,
    setExplainingId,
  ] =
    useState<number | null>(
      null
    );


  const [
    error,
    setError,
  ] =
    useState("");


  const [
    operationError,
    setOperationError,
  ] =
    useState("");


  function triageListToMap(
    results:
      ArtifactTriageResult[]
  ) {

    const map:
      Record<
        number,
        ArtifactTriageResult
      >
      = {};


    for (
      const result
      of results
    ) {

      map[
        result.evidence_id
      ] = result;
    }


    return map;
  }


  function attentionListToMap(
    records:
      EvidenceAttention[]
  ) {

    const map:
      Record<
        number,
        EvidenceAttention
      >
      = {};


    for (
      const record
      of records
    ) {

      map[
        record.evidence_id
      ] = record;
    }


    return map;
  }


  /* ====================================================
     REFRESH HELPERS
  ==================================================== */


  async function refreshCoverage() {

    const result =
      await getCaseCoverage(
        caseId
      );


    setCoverageReport(
      result
    );


    setSelectedCoverage(
      (current) => {

        if (!current) {

          return (
            result
              .evidence_coverage[0]
            ??
            null
          );
        }


        return (
          result
            .evidence_coverage
            .find(
              (item) =>
                item.evidence_id
                === current.evidence_id
            )
          ??
          result
            .evidence_coverage[0]
          ??
          null
        );
      }
    );
  }


  async function refreshAttentionAndCoverage() {

    const [
      attentionData,
      coverageData,
    ] =
      await Promise.all([

        getCaseAttention(
          caseId
        ),

        getCaseCoverage(
          caseId
        ),

      ]);


    setAttentionRecords(
      attentionListToMap(
        attentionData
      )
    );


    setCoverageReport(
      coverageData
    );


    setSelectedCoverage(
      (current) => {

        if (!current) {

          return (
            coverageData
              .evidence_coverage[0]
            ??
            null
          );
        }


        return (
          coverageData
            .evidence_coverage
            .find(
              (item) =>
                item.evidence_id
                === current.evidence_id
            )
          ??
          coverageData
            .evidence_coverage[0]
          ??
          null
        );
      }
    );
  }


  async function refreshBlindSpots() {

    const result =
      await getBlindSpots(
        caseId
      );


    setBlindSpotReport(
      result
    );


    setSelectedBlindSpot(
      (current) => {

        if (!current) {

          return (
            result.blind_spots[0]
            ??
            null
          );
        }


        return (
          result.blind_spots
            .find(
              (item) =>
                item.evidence_id
                === current.evidence_id
            )
          ??
          result.blind_spots[0]
          ??
          null
        );
      }
    );
  }


  async function refreshAnalystBrief() {

    const result =
      await getAnalystBrief(
        caseId
      );


    setAnalystBrief(
      result
    );
  }


  async function refreshGraph() {

    const graphData =
      await getEvidenceGraph(
        caseId
      );


    setGraph(
      graphData
    );


    setSelectedGraphNode(
      (current) => {

        if (!current) {

          return (
            graphData.nodes[0]
            ??
            null
          );
        }


        return (
          graphData.nodes.find(
            (node) =>
              node.id
              === current.id
          )
          ??
          graphData.nodes[0]
          ??
          null
        );
      }
    );
  }


  /* ====================================================
     INITIAL LOAD
  ==================================================== */


  async function loadAll() {

    const [
      caseData,
      evidenceData,
      ledgerData,
      predictionData,
      triageData,
      attentionData,
      coverageData,
      blindSpotData,
      analystBriefData,
      graphData,
    ] =
      await Promise.all([

        getCase(
          caseId
        ),

        getCaseEvidence(
          caseId
        ),

        getCaseLedger(
          caseId
        ),

        getCasePredictions(
          caseId
        ),

        getCaseArtifactTriage(
          caseId
        ),

        getCaseAttention(
          caseId
        ),

        getCaseCoverage(
          caseId
        ),

        getBlindSpots(
          caseId
        ),

        getAnalystBrief(
          caseId
        ),

        getEvidenceGraph(
          caseId
        ),

      ]);


    setForensicCase(
      caseData
    );


    setEvidence(
      evidenceData
    );


    setLedger(
      ledgerData
    );


    setPredictions(
      predictionData
    );


    setTriageResults(
      triageListToMap(
        triageData
      )
    );


    setAttentionRecords(
      attentionListToMap(
        attentionData
      )
    );


    setCoverageReport(
      coverageData
    );


    setSelectedCoverage(
      coverageData
        .evidence_coverage[0]
      ??
      null
    );


    setBlindSpotReport(
      blindSpotData
    );


    setSelectedBlindSpot(
      blindSpotData
        .blind_spots[0]
      ??
      null
    );


    setAnalystBrief(
      analystBriefData
    );


    setSelectedEvidence(
      evidenceData[0]
      ??
      null
    );


    setGraph(
      graphData
    );


    setSelectedGraphNode(
      graphData.nodes[0]
      ??
      null
    );
  }


  useEffect(() => {

    if (
      !Number.isInteger(
        caseId
      )
      ||
      caseId < 1
    ) {

      setError(
        "Invalid forensic case."
      );


      setLoading(
        false
      );


      return;
    }


    async function load() {

      try {

        await loadAll();

      } catch (error) {

        setError(
          error instanceof Error
            ? error.message
            : "Unable to load case."
        );

      } finally {

        setLoading(
          false
        );
      }
    }


    void load();

  }, [
    caseId
  ]);


  useEffect(() => {

    if (
      activeTab === "coverage"
    ) {

      void refreshCoverage();
    }


    if (
      activeTab === "blindspots"
    ) {

      void refreshBlindSpots();
    }


    if (
      activeTab === "analyst"
    ) {

      void refreshAnalystBrief();
    }

  }, [
    activeTab
  ]);


  /* ====================================================
     ATTENTION TRACKING
  ==================================================== */


  useEffect(() => {

    const trackableTab =
      activeTab === "evidence"
      ||
      activeTab === "triage";


    if (
      !trackableTab
      ||
      !selectedEvidence
    ) {

      return;
    }


    const evidenceId =
      selectedEvidence.id;


    const startedAt =
      Date.now();


    let focusedMilliseconds =
      0;


    let focusStartedAt:
      number | null =
        document.visibilityState
        === "visible"
          ? Date.now()
          : null;


    void recordEvidenceAttention(
      caseId,
      evidenceId,
      {
        dwell_seconds: 0,
        focused_seconds: 0,
        new_view: true,
      }
    )
      .then(
        () =>
          refreshAttentionAndCoverage()
      )
      .catch(
        () => {
          // Telemetry must never break UI.
        }
      );


    function handleVisibilityChange() {

      const now =
        Date.now();


      if (
        document.visibilityState
        === "hidden"
      ) {

        if (
          focusStartedAt
          !== null
        ) {

          focusedMilliseconds += (
            now
            -
            focusStartedAt
          );


          focusStartedAt =
            null;
        }

      } else {

        if (
          focusStartedAt
          === null
        ) {

          focusStartedAt =
            now;
        }
      }
    }


    document.addEventListener(
      "visibilitychange",
      handleVisibilityChange
    );


    return () => {

      document.removeEventListener(
        "visibilitychange",
        handleVisibilityChange
      );


      const endedAt =
        Date.now();


      if (
        focusStartedAt
        !== null
      ) {

        focusedMilliseconds += (
          endedAt
          -
          focusStartedAt
        );
      }


      const dwellSeconds =
        Math.max(
          0,
          (
            endedAt
            -
            startedAt
          )
          /
          1000
        );


      const focusedSeconds =
        Math.max(
          0,
          Math.min(
            focusedMilliseconds
            /
            1000,
            dwellSeconds
          )
        );


      void recordEvidenceAttention(
        caseId,
        evidenceId,
        {
          dwell_seconds:
            Number(
              dwellSeconds.toFixed(
                2
              )
            ),

          focused_seconds:
            Number(
              focusedSeconds.toFixed(
                2
              )
            ),

          new_view:
            false,
        }
      )
        .then(
          async () => {

            await refreshAttentionAndCoverage();

            await refreshBlindSpots();

          }
        )
        .catch(
          () => {
            // Never block navigation.
          }
        );
    };

  }, [
    caseId,
    activeTab,
    selectedEvidence?.id,
  ]);


  useEffect(() => {

    setExplanation(
      null
    );

  }, [
    selectedEvidence?.id
  ]);


  /* ====================================================
     FORENSIC ACTIONS
  ==================================================== */


  async function handleFileSelected(
    event:
      ChangeEvent<HTMLInputElement>
  ) {

    const file =
      event.target.files?.[0];


    if (!file) {
      return;
    }


    setUploading(
      true
    );


    setOperationError(
      ""
    );


    try {

      const uploaded =
        await uploadEvidence(
          caseId,
          file
        );


      const evidenceData =
        await getCaseEvidence(
          caseId
        );


      setEvidence(
        evidenceData
      );


      setSelectedEvidence(
        evidenceData.find(
          (item) =>
            item.id
            === uploaded.id
        )
        ??
        uploaded
      );


      setLedger(
        await getCaseLedger(
          caseId
        )
      );


      await refreshGraph();

      await refreshAttentionAndCoverage();

      await refreshBlindSpots();

      await refreshAnalystBrief();


      setActiveTab(
        "evidence"
      );


    } catch (error) {

      setOperationError(
        error instanceof Error
          ? error.message
          : "Evidence upload failed."
      );

    } finally {

      setUploading(
        false
      );


      event.target.value =
        "";
    }
  }


  async function handleVerify(
    item: Evidence
  ) {

    setVerifyingId(
      item.id
    );


    setOperationError(
      ""
    );


    try {

      const verified =
        await verifyEvidenceIntegrity(
          caseId,
          item.id
        );


      setEvidence(
        (current) =>
          current.map(
            (entry) =>
              entry.id
              === verified.id
                ? verified
                : entry
          )
      );


      setSelectedEvidence(
        (current) =>
          current?.id
          === verified.id
            ? verified
            : current
      );


      setLedger(
        await getCaseLedger(
          caseId
        )
      );


      await refreshCoverage();

      await refreshBlindSpots();

      await refreshAnalystBrief();


    } catch (error) {

      setOperationError(
        error instanceof Error
          ? error.message
          : "Integrity verification failed."
      );

    } finally {

      setVerifyingId(
        null
      );
    }
  }


  async function handleForensicTriage(
    item: Evidence
  ) {

    setTriagingId(
      item.id
    );


    setOperationError(
      ""
    );


    setExplanation(
      null
    );


    try {

      const triage =
        await runArtifactTriage(
          caseId,
          item.id
        );


      setTriageResults(
        (current) => ({
          ...current,

          [item.id]:
            triage,
        })
      );


      if (
        isPEFile(
          item
        )
      ) {

        const prediction =
          await runMLTriage(
            caseId,
            item.id
          );


        setPredictions(
          (current) => {

            const remaining =
              current.filter(
                (entry) =>
                  entry.evidence_id
                  !== prediction.evidence_id
              );


            return [
              prediction,
              ...remaining,
            ];
          }
        );
      }


      setLedger(
        await getCaseLedger(
          caseId
        )
      );


      await refreshCoverage();

      await refreshBlindSpots();

      await refreshGraph();

      await refreshAnalystBrief();


    } catch (error) {

      setOperationError(
        error instanceof Error
          ? error.message
          : "Forensic triage failed."
      );

    } finally {

      setTriagingId(
        null
      );
    }
  }


  async function handleExplain(
    item: Evidence
  ) {

    setExplainingId(
      item.id
    );


    setOperationError(
      ""
    );


    try {

      const result =
        await getMLExplanation(
          caseId,
          item.id
        );


      setExplanation(
        result
      );


      setLedger(
        await getCaseLedger(
          caseId
        )
      );


    } catch (error) {

      setOperationError(
        error instanceof Error
          ? error.message
          : "Unable to explain ML result."
      );

    } finally {

      setExplainingId(
        null
      );
    }
  }


  async function handleGraphRebuild() {

    setGraphLoading(
      true
    );


    setOperationError(
      ""
    );


    try {

      const rebuilt =
        await rebuildEvidenceGraph(
          caseId
        );


      setGraph(
        rebuilt
      );


      setSelectedGraphNode(
        rebuilt.nodes[0]
        ??
        null
      );


      setSelectedGraphEdge(
        null
      );


      setSelectedGraphCluster(
        null
      );


      setLedger(
        await getCaseLedger(
          caseId
        )
      );


      await refreshAnalystBrief();


    } catch (error) {

      setOperationError(
        error instanceof Error
          ? error.message
          : "Graph rebuild failed."
      );

    } finally {

      setGraphLoading(
        false
      );
    }
  }


  async function handleBlindSpotRecalculate() {

    setBlindSpotLoading(
      true
    );


    setOperationError(
      ""
    );


    try {

      const result =
        await recalculateBlindSpots(
          caseId
        );


      setBlindSpotReport(
        result
      );


      setSelectedBlindSpot(
        result.blind_spots[0]
        ??
        null
      );


      setLedger(
        await getCaseLedger(
          caseId
        )
      );


      await refreshAnalystBrief();


    } catch (error) {

      setOperationError(
        error instanceof Error
          ? error.message
          : "Blind Spot recalculation failed."
      );

    } finally {

      setBlindSpotLoading(
        false
      );
    }
  }


  /* ====================================================
     AI ANALYST
  ==================================================== */


  async function handleAskAnalyst(
    overrideQuestion?: string
  ) {

    const question =
      (
        overrideQuestion
        ??
        analystInput
      )
      .trim();


    if (
      !question
      ||
      analystLoading
    ) {

      return;
    }


    setOperationError(
      ""
    );


    setAnalystInput(
      ""
    );


    setAnalystMessages(
      (current) => [
        ...current,

        {
          id:
            `${Date.now()}-user`,

          role:
            "user",

          text:
            question,
        },
      ]
    );


    setAnalystLoading(
      true
    );


    try {

      const response =
        await askAnalyst(
          caseId,
          question
        );


      setAnalystMessages(
        (current) => [
          ...current,

          {
            id:
              `${Date.now()}-assistant`,

            role:
              "assistant",

            text:
              response.answer,

            response,
          },
        ]
      );


      setLedger(
        await getCaseLedger(
          caseId
        )
      );


      await refreshAnalystBrief();


    } catch (error) {

      const message =
        error instanceof Error
          ? error.message
          : "AI Analyst request failed.";


      setOperationError(
        message
      );


      setAnalystMessages(
        (current) => [
          ...current,

          {
            id:
              `${Date.now()}-error`,

            role:
              "assistant",

            text:
              `Unable to complete the analyst request: ${message}`,
          },
        ]
      );

    } finally {

      setAnalystLoading(
        false
      );
    }
  }


  function handleAnalystSubmit(
    event:
      FormEvent<HTMLFormElement>
  ) {

    event.preventDefault();

    void handleAskAnalyst();
  }


  /* ====================================================
     NAVIGATION
  ==================================================== */


  function reviewEvidence(
    evidenceId: number
  ) {

    const target =
      evidence.find(
        (item) =>
          item.id
          === evidenceId
      );


    if (!target) {

      setOperationError(
        `Evidence ID ${evidenceId} could not be found in the current case.`
      );

      return;
    }


    setSelectedEvidence(
      target
    );


    setActiveTab(
      "evidence"
    );
  }


  function openEvidenceByCode(
    evidenceCode: string
  ) {

    const target =
      evidence.find(
        (item) =>
          item.evidence_code
          === evidenceCode
      );


    if (!target) {

      setOperationError(
        `${evidenceCode} could not be found in the current evidence list.`
      );

      return;
    }


    setSelectedEvidence(
      target
    );


    setActiveTab(
      "evidence"
    );
  }


  function openGraphEdge(
    edge: GraphEdge
  ) {

    setSelectedGraphEdge(
      edge
    );


    setSelectedGraphNode(
      null
    );


    setSelectedGraphCluster(
      null
    );


    setActiveTab(
      "graph"
    );
  }


  function openGraphCluster(
    cluster: GraphCluster
  ) {

    setSelectedGraphCluster(
      cluster
    );


    setSelectedGraphNode(
      null
    );


    setSelectedGraphEdge(
      null
    );


    setActiveTab(
      "graph"
    );
  }


  /* ====================================================
     SELECTED DATA
  ==================================================== */


  const selectedTriage =
    selectedEvidence
      ? triageResults[
          selectedEvidence.id
        ]
        ??
        null
      : null;


  const selectedPrediction =
    selectedEvidence
      ? predictions.find(
          (prediction) =>
            prediction.evidence_id
            === selectedEvidence.id
        )
        ??
        null
      : null;


  const analyzedCount =
    Object.keys(
      triageResults
    ).length;


  /* ====================================================
     GRAPH POSITIONS
  ==================================================== */


  const graphPositions =
    useMemo(() => {

      const result =
        new Map<
          string,
          Point
        >();


      if (
        !graph
        ||
        graph.nodes.length === 0
      ) {

        return result;
      }


      const caseNode =
        graph.nodes.find(
          (node) =>
            node.type
            === "case"
        );


      if (caseNode) {

        result.set(
          caseNode.id,
          {
            x: 450,
            y: 290,
          }
        );
      }


      const evidenceNodes =
        graph.nodes.filter(
          (node) =>
            node.type
            === "evidence"
        );


      const radius =
        evidenceNodes.length <= 6
          ? 205
          : 230;


      evidenceNodes.forEach(
        (
          node,
          index
        ) => {

          const angle =
            (
              Math.PI
              *
              2
              *
              index
            )
            /
            Math.max(
              evidenceNodes.length,
              1
            )
            -
            Math.PI / 2;


          result.set(
            node.id,
            {
              x:
                450
                +
                Math.cos(
                  angle
                )
                *
                radius,

              y:
                290
                +
                Math.sin(
                  angle
                )
                *
                radius,
            }
          );
        }
      );


      return result;

    }, [
      graph
    ]);


  /* ====================================================
     LOADING
  ==================================================== */


  if (loading) {

    return (

      <main className="centerScreen">
        Loading investigation...
      </main>
    );
  }


  if (
    error
    ||
    !forensicCase
  ) {

    return (

      <main className="centerScreen">

        {
          error
          ||
          "Case unavailable"
        }

      </main>
    );
  }


  /* ====================================================
     UI
  ==================================================== */


  return (

    <main className="workspace">

      <aside className="sidebar">

        <Link
          href="/"
          className="brand"
          aria-label="SYNAPSE home"
        >

          <img
            src="/synapse-icon.png"
            alt="SYNAPSE"
            className="brandIcon"
          />

          <div>

            <strong>
              SYNAPSE
            </strong>

            <small>
              HUMAN-AWARE FORENSICS
            </small>

          </div>

        </Link>


        <nav>

          <button
            type="button"
            className={
              activeTab === "overview"
                ? "active"
                : ""
            }
            onClick={() =>
              setActiveTab(
                "overview"
              )
            }
          >
            Overview
          </button>


          <button
            type="button"
            className={
              activeTab === "evidence"
                ? "active"
                : ""
            }
            onClick={() =>
              setActiveTab(
                "evidence"
              )
            }
          >
            Evidence
          </button>


          <button
            type="button"
            className={
              activeTab === "graph"
                ? "active"
                : ""
            }
            onClick={() =>
              setActiveTab(
                "graph"
              )
            }
          >
            Evidence Graph
          </button>


          <button
            type="button"
            className={
              activeTab === "triage"
                ? "active"
                : ""
            }
            onClick={() =>
              setActiveTab(
                "triage"
              )
            }
          >
            Forensic Triage
          </button>


          <button
            type="button"
            className={
              activeTab === "analyst"
                ? "active"
                : ""
            }
            onClick={() =>
              setActiveTab(
                "analyst"
              )
            }
          >
            AI Analyst
          </button>


          <button
            type="button"
            className={
              activeTab === "blindspots"
                ? "active"
                : ""
            }
            onClick={() =>
              setActiveTab(
                "blindspots"
              )
            }
          >
            Blind Spots
          </button>


          <button
            type="button"
            className={
              activeTab === "coverage"
                ? "active"
                : ""
            }
            onClick={() =>
              setActiveTab(
                "coverage"
              )
            }
          >
            Coverage
          </button>


          <button
            type="button"
            className={
              activeTab === "timeline"
                ? "active"
                : ""
            }
            onClick={() =>
              setActiveTab(
                "timeline"
              )
            }
          >
            Timeline
          </button>


          <button
            type="button"
            className={
              activeTab === "ledger"
                ? "active"
                : ""
            }
            onClick={() =>
              setActiveTab(
                "ledger"
              )
            }
          >
            Chain of Custody
          </button>


          <button
            type="button"
            className={
              activeTab === "report"
                ? "active"
                : ""
            }
            onClick={() =>
              setActiveTab(
                "report"
              )
            }
          >
            Report
          </button>

        </nav>

      </aside>


      <section className="workspaceMain">

        <header className="workspaceHeader">

          <div>

            <span className="eyebrow">
              {
                forensicCase.case_code
              }
            </span>


            <strong>
              {
                forensicCase.name
              }
            </strong>

          </div>


          <span className="activeBadge">
            ● {
              forensicCase.status
            }
          </span>

        </header>


        <div className="workspaceBody">

          {
            operationError
            &&
            (

              <div className="formError">
                {
                  operationError
                }
              </div>
            )
          }


          {/* =================================================
              OVERVIEW
          ================================================= */}


          {
            activeTab === "overview"
            &&
            (

              <>

                <section className="caseOverview">

                  <span className="eyebrow">
                    HUMAN-AWARE CYBER FORENSICS
                  </span>


                  <h1>
                    {
                      forensicCase.name
                    }
                  </h1>


                  <p>
                    {
                      forensicCase.description
                      ||
                      "No investigation description provided."
                    }
                  </p>


                  <div className="overviewInfo">

                    <div>

                      <span>
                        INVESTIGATOR
                      </span>

                      <strong>
                        {
                          forensicCase.investigator
                        }
                      </strong>

                    </div>


                    <div>

                      <span>
                        AVG COVERAGE
                      </span>

                      <strong>
                        {
                          coverageReport
                            ?.summary
                            .average_coverage
                          ??
                          0
                        }%
                      </strong>

                    </div>

                  </div>

                </section>


                <section className="phaseStats">

                  <article>

                    <span>
                      EVIDENCE
                    </span>

                    <strong>
                      {
                        evidence.length
                      }
                    </strong>

                  </article>


                  <article>

                    <span>
                      ANALYZED
                    </span>

                    <strong>
                      {
                        analyzedCount
                      }
                    </strong>

                  </article>


                  <article>

                    <span>
                      CORRELATIONS
                    </span>

                    <strong>
                      {
                        graph
                          ?.summary
                          .correlation_links
                        ??
                        0
                      }
                    </strong>

                  </article>


                  <article>

                    <span>
                      HIGH BLIND SPOTS
                    </span>

                    <strong>
                      {
                        blindSpotReport
                          ?.summary
                          .high_blind_spots
                        ??
                        0
                      }
                    </strong>

                  </article>

                </section>


                <section className="nextModule">

                  <div>

                    <span className="eyebrow">
                      INVESTIGATION RECONSTRUCTION
                    </span>


                    <h2>
                      Timeline + Replay
                    </h2>


                    <p>
                      Reconstruct the investigation
                      chronologically from evidence
                      registration through forensic analysis,
                      review activity, correlation and AI
                      assistance.
                    </p>

                  </div>


                  <button
                    type="button"
                    onClick={() =>
                      setActiveTab(
                        "timeline"
                      )
                    }
                  >
                    Open Timeline
                  </button>

                </section>

              </>

            )
          }


          {/* =================================================
              EVIDENCE
          ================================================= */}


          {
            activeTab === "evidence"
            &&
            (

              <section className="evidenceWorkspace">

                <div className="evidencePanel">

                  <div className="sectionHeader">

                    <div>

                      <span className="eyebrow">
                        EVIDENCE EXPLORER
                      </span>

                      <h2>
                        Registered Evidence
                      </h2>

                    </div>


                    <button
                      type="button"
                      disabled={
                        uploading
                      }
                      onClick={() =>
                        fileInputRef
                          .current
                          ?.click()
                      }
                    >
                      {
                        uploading
                          ? "Uploading..."
                          : "+ Add Evidence"
                      }
                    </button>

                  </div>


                  <input
                    ref={
                      fileInputRef
                    }
                    type="file"
                    hidden
                    onChange={
                      handleFileSelected
                    }
                  />


                  <div className="evidenceList">

                    {
                      evidence.map(
                        (item) => {

                          const attention =
                            attentionRecords[
                              item.id
                            ];


                          const triage =
                            triageResults[
                              item.id
                            ];


                          return (

                            <button
                              type="button"
                              key={
                                item.id
                              }
                              className={
                                `evidenceRow ${
                                  selectedEvidence?.id
                                  === item.id
                                    ? "selected"
                                    : ""
                                }`
                              }
                              onClick={() =>
                                setSelectedEvidence(
                                  item
                                )
                              }
                            >

                              <div className="evidenceRowMain">

                                <strong>
                                  {
                                    item.original_filename
                                  }
                                </strong>


                                <span>
                                  {
                                    item.evidence_code
                                  }
                                </span>

                              </div>


                              <div className="evidenceMeta">

                                <span>
                                  {
                                    item.file_extension
                                  }
                                </span>


                                <span>
                                  {
                                    attention
                                      ? `${attention.view_count} views`
                                      : "UNREVIEWED"
                                  }
                                </span>


                                <span>
                                  {
                                    triage
                                      ? `${triage.risk_score}% risk`
                                      : "Not triaged"
                                  }
                                </span>

                              </div>

                            </button>

                          );
                        }
                      )
                    }

                  </div>

                </div>


                <aside className="inspectorPanel">

                  {
                    selectedEvidence
                    &&
                    (

                      <>

                        <div className="inspectorTop">

                          <div>

                            <span className="eyebrow">
                              ARTIFACT INSPECTOR
                            </span>


                            <h3>
                              {
                                selectedEvidence
                                  .original_filename
                              }
                            </h3>


                            <span className="artifactCode">
                              {
                                selectedEvidence
                                  .evidence_code
                              }
                            </span>

                          </div>

                        </div>


                        <div className="inspectorGrid">

                          <div>

                            <span>
                              TYPE
                            </span>

                            <strong>
                              {
                                selectedEvidence
                                  .file_extension
                              }
                            </strong>

                          </div>


                          <div>

                            <span>
                              SIZE
                            </span>

                            <strong>
                              {
                                formatBytes(
                                  selectedEvidence
                                    .file_size
                                )
                              }
                            </strong>

                          </div>


                          <div>

                            <span>
                              ENTROPY
                            </span>

                            <strong>
                              {
                                selectedEvidence
                                  .entropy
                              }
                            </strong>

                          </div>


                          <div>

                            <span>
                              INTEGRITY
                            </span>

                            <strong>
                              {
                                selectedEvidence
                                  .integrity_status
                              }
                            </strong>

                          </div>

                        </div>


                        <div className="hashSection">

                          <div className="hashItem">

                            <span>
                              SHA-256
                            </span>

                            <code>
                              {
                                selectedEvidence.sha256
                              }
                            </code>

                          </div>


                          <div className="hashItem">

                            <span>
                              SHA-1
                            </span>

                            <code>
                              {
                                selectedEvidence.sha1
                              }
                            </code>

                          </div>


                          <div className="hashItem">

                            <span>
                              MD5
                            </span>

                            <code>
                              {
                                selectedEvidence.md5
                              }
                            </code>

                          </div>

                        </div>


                        <div className="integrityCard">

                          <div>

                            <span className="eyebrow">
                              INTEGRITY
                            </span>


                            <strong>
                              {
                                selectedEvidence
                                  .integrity_status
                              }
                            </strong>

                          </div>


                          <button
                            type="button"
                            disabled={
                              verifyingId
                              === selectedEvidence.id
                            }
                            onClick={() =>
                              void handleVerify(
                                selectedEvidence
                              )
                            }
                          >
                            {
                              verifyingId
                              === selectedEvidence.id
                                ? "Verifying..."
                                : "Verify Integrity"
                            }
                          </button>

                        </div>

                      </>

                    )
                  }

                </aside>

              </section>

            )
          }


          {/* =================================================
              TRIAGE
          ================================================= */}


          {
            activeTab === "triage"
            &&
            (

              <section className="evidenceWorkspace">

                <div className="evidencePanel">

                  <div className="sectionHeader">

                    <div>

                      <span className="eyebrow">
                        FORENSIC TRIAGE
                      </span>

                      <h2>
                        Multi-Artifact Queue
                      </h2>

                    </div>

                  </div>


                  <div className="evidenceList">

                    {
                      evidence.map(
                        (item) => {

                          const result =
                            triageResults[
                              item.id
                            ];


                          return (

                            <button
                              type="button"
                              key={
                                item.id
                              }
                              className={
                                `evidenceRow ${
                                  selectedEvidence?.id
                                  === item.id
                                    ? "selected"
                                    : ""
                                }`
                              }
                              onClick={() =>
                                setSelectedEvidence(
                                  item
                                )
                              }
                            >

                              <div className="evidenceRowMain">

                                <strong>
                                  {
                                    item.original_filename
                                  }
                                </strong>


                                <span>
                                  {
                                    analyzerName(
                                      item.file_extension
                                    )
                                  }
                                </span>

                              </div>


                              {
                                result
                                ? (

                                  <span
                                    style={{
                                      color:
                                        getRiskColor(
                                          result.risk_level
                                        ),

                                      fontWeight:
                                        700,
                                    }}
                                  >
                                    {
                                      result.risk_score
                                    }%
                                    {" · "}
                                    {
                                      result.risk_level
                                    }
                                  </span>

                                )
                                : (

                                  <span className="integrityBadge">
                                    READY
                                  </span>

                                )
                              }

                            </button>

                          );
                        }
                      )
                    }

                  </div>

                </div>


                <aside className="inspectorPanel">

                  {
                    selectedEvidence
                    &&
                    (

                      <>

                        <div className="inspectorTop">

                          <div>

                            <span className="eyebrow">
                              FORENSIC TRIAGE
                            </span>


                            <h3>
                              {
                                selectedEvidence
                                  .original_filename
                              }
                            </h3>


                            <span className="artifactCode">
                              {
                                analyzerName(
                                  selectedEvidence
                                    .file_extension
                                )
                              }
                            </span>

                          </div>

                        </div>


                        {
                          selectedTriage
                          ? (

                            <>

                              <div
                                className="integrityCard"
                                style={{
                                  borderColor:
                                    getRiskColor(
                                      selectedTriage
                                        .risk_level
                                    ),
                                }}
                              >

                                <div>

                                  <span className="eyebrow">
                                    FORENSIC RISK
                                  </span>


                                  <strong
                                    style={{
                                      color:
                                        getRiskColor(
                                          selectedTriage
                                            .risk_level
                                        ),

                                      fontSize:
                                        "26px",
                                    }}
                                  >
                                    {
                                      selectedTriage
                                        .risk_score
                                    }%
                                  </strong>


                                  <p>
                                    {
                                      selectedTriage
                                        .risk_level
                                    }
                                  </p>

                                </div>


                                <button
                                  type="button"
                                  disabled={
                                    triagingId
                                    === selectedEvidence.id
                                  }
                                  onClick={() =>
                                    void handleForensicTriage(
                                      selectedEvidence
                                    )
                                  }
                                >
                                  {
                                    triagingId
                                    === selectedEvidence.id
                                      ? "Analyzing..."
                                      : "Analyze Again"
                                  }
                                </button>

                              </div>


                              {
                                selectedTriage
                                  .indicators
                                  .length > 0
                                &&
                                (

                                  <div className="integrityCard">

                                    <div
                                      style={{
                                        width:
                                          "100%",
                                      }}
                                    >

                                      <span className="eyebrow">
                                        EXTRACTED INDICATORS
                                      </span>


                                      {
                                        selectedTriage
                                          .indicators
                                          .map(
                                            (
                                              indicator,
                                              index
                                            ) => (

                                              <p
                                                key={
                                                  `${indicator.type}-${indicator.value}-${index}`
                                                }
                                                style={{
                                                  marginTop:
                                                    "8px",

                                                  wordBreak:
                                                    "break-word",
                                                }}
                                              >
                                                <strong>
                                                  {
                                                    indicator.type
                                                  }
                                                </strong>
                                                :
                                                {" "}
                                                {
                                                  indicator.value
                                                }
                                              </p>

                                            )
                                          )
                                      }

                                    </div>

                                  </div>

                                )
                              }


                              {
                                selectedTriage.findings
                                  .map(
                                    (
                                      finding,
                                      index
                                    ) => (

                                      <div
                                        className="integrityCard"
                                        key={
                                          `${finding.title}-${index}`
                                        }
                                        style={{
                                          borderColor:
                                            `${getFindingColor(
                                              finding.severity
                                            )}55`,
                                        }}
                                      >

                                        <div>

                                          <span
                                            className="eyebrow"
                                            style={{
                                              color:
                                                getFindingColor(
                                                  finding.severity
                                                ),
                                            }}
                                          >
                                            {
                                              finding.severity
                                            }
                                          </span>


                                          <strong>
                                            {
                                              finding.title
                                            }
                                          </strong>


                                          <p>
                                            {
                                              finding.detail
                                            }
                                          </p>

                                        </div>

                                      </div>

                                    )
                                  )
                              }


                              {
                                selectedTriage
                                  .limitations
                                &&
                                (

                                  <div className="inspectorHint">

                                    <span className="eyebrow">
                                      ANALYSIS LIMITATIONS
                                    </span>


                                    <p
                                      style={{
                                        marginTop:
                                          "8px",

                                        lineHeight:
                                          "1.6",
                                      }}
                                    >
                                      {
                                        selectedTriage
                                          .limitations
                                      }
                                    </p>

                                  </div>

                                )
                              }


                              {
                                isPEFile(
                                  selectedEvidence
                                )
                                &&
                                selectedPrediction
                                &&
                                (

                                  <div className="integrityCard">

                                    <div>

                                      <span className="eyebrow">
                                        EXPLAINABLE ML
                                      </span>


                                      <strong>
                                        Explain PE classification
                                      </strong>

                                    </div>


                                    <button
                                      type="button"
                                      disabled={
                                        explainingId
                                        === selectedEvidence.id
                                      }
                                      onClick={() =>
                                        void handleExplain(
                                          selectedEvidence
                                        )
                                      }
                                    >
                                      {
                                        explainingId
                                        === selectedEvidence.id
                                          ? "Explaining..."
                                          : "Explain"
                                      }
                                    </button>

                                  </div>

                                )
                              }


                              {
                                explanation
                                &&
                                (

                                  <div className="inspectorHint">

                                    <span className="eyebrow">
                                      MODEL EXPLANATION
                                    </span>


                                    <strong
                                      style={{
                                        display:
                                          "block",

                                        marginTop:
                                          "8px",
                                      }}
                                    >
                                      {
                                        explanation.summary
                                      }
                                    </strong>


                                    {
                                      explanation
                                        .top_features
                                        .map(
                                          (
                                            feature,
                                            index
                                          ) => (

                                            <div
                                              key={
                                                `${feature.feature}-${index}`
                                              }
                                              style={{
                                                marginTop:
                                                  "9px",

                                                paddingTop:
                                                  "8px",

                                                borderTop:
                                                  "1px solid var(--border)",
                                              }}
                                            >

                                              <strong>
                                                {
                                                  feature.label
                                                }
                                              </strong>


                                              <p>
                                                {
                                                  feature.display_value
                                                }
                                                {" · Importance "}
                                                {
                                                  feature.importance_percent
                                                }%
                                              </p>


                                              <p
                                                style={{
                                                  opacity:
                                                    0.7,
                                                }}
                                              >
                                                {
                                                  feature.interpretation
                                                }
                                              </p>

                                            </div>

                                          )
                                        )
                                    }

                                  </div>

                                )
                              }

                            </>

                          )
                          : (

                            <div className="integrityCard">

                              <div>

                                <span className="eyebrow">
                                  READY FOR ANALYSIS
                                </span>


                                <strong>
                                  {
                                    analyzerName(
                                      selectedEvidence
                                        .file_extension
                                    )
                                  }
                                </strong>

                              </div>


                              <button
                                type="button"
                                disabled={
                                  triagingId
                                  === selectedEvidence.id
                                }
                                onClick={() =>
                                  void handleForensicTriage(
                                    selectedEvidence
                                  )
                                }
                              >
                                {
                                  triagingId
                                  === selectedEvidence.id
                                    ? "Analyzing..."
                                    : "Run Forensic Triage"
                                }
                              </button>

                            </div>

                          )
                        }

                      </>

                    )
                  }

                </aside>

              </section>

            )
          }


          {/* =================================================
              ADVANCED EVIDENCE GRAPH
          ================================================= */}


          {
            activeTab === "graph"
            &&
            graph
            &&
            (

              <>

                <section className="phaseStats">

                  <article>

                    <span>
                      CORRELATED
                    </span>

                    <strong>
                      {
                        graph.summary
                          .correlated_evidence
                      }
                    </strong>

                  </article>


                  <article>

                    <span>
                      RELATIONSHIPS
                    </span>

                    <strong>
                      {
                        graph.summary
                          .correlation_links
                      }
                    </strong>

                  </article>


                  <article>

                    <span>
                      STRONG
                    </span>

                    <strong
                      style={{
                        color:
                          "#ff996e",
                      }}
                    >
                      {
                        graph.summary
                          .strong_correlations
                      }
                    </strong>

                  </article>


                  <article>

                    <span>
                      CLUSTERS
                    </span>

                    <strong>
                      {
                        graph.summary
                          .clusters
                      }
                    </strong>

                  </article>

                </section>


                <section
                  style={{
                    display:
                      "grid",

                    gridTemplateColumns:
                      "minmax(0, 1fr) 350px",

                    gap:
                      "18px",

                    marginTop:
                      "18px",
                  }}
                >

                  <div>

                    <div
                      style={{
                        border:
                          "1px solid var(--border)",

                        borderRadius:
                          "18px",

                        background:
                          "var(--panel)",

                        overflow:
                          "hidden",
                      }}
                    >

                      <div
                        className="sectionHeader"
                        style={{
                          padding:
                            "18px 20px",
                        }}
                      >

                        <div>

                          <span className="eyebrow">
                            ADVANCED CORRELATION MAP
                          </span>


                          <h2>
                            Evidence Graph
                          </h2>

                        </div>


                        <button
                          type="button"
                          disabled={
                            graphLoading
                          }
                          onClick={() =>
                            void handleGraphRebuild()
                          }
                        >
                          {
                            graphLoading
                              ? "Rebuilding..."
                              : "Rebuild Graph"
                          }
                        </button>

                      </div>


                      <div
                        style={{
                          display:
                            "flex",

                          flexWrap:
                            "wrap",

                          gap:
                            "8px",

                          padding:
                            "0 20px 14px",
                        }}
                      >

                        {
                          [
                            [
                              "Exact Duplicate",
                              "SAME_SHA256",
                            ],

                            [
                              "Shared IP",
                              "SHARED_IP",
                            ],

                            [
                              "Shared Domain",
                              "SHARED_DOMAIN",
                            ],

                            [
                              "Shared URL",
                              "SHARED_URL",
                            ],

                            [
                              "Shared Hash",
                              "SHARED_HASH",
                            ],

                            [
                              "Filename Collision",
                              "SAME_FILENAME_DIFFERENT_HASH",
                            ],
                          ]
                          .map(
                            (
                              [
                                label,
                                type,
                              ]
                            ) => (

                              <span
                                key={
                                  type
                                }
                                style={{
                                  display:
                                    "inline-flex",

                                  alignItems:
                                    "center",

                                  gap:
                                    "6px",

                                  padding:
                                    "6px 9px",

                                  border:
                                    "1px solid var(--border)",

                                  borderRadius:
                                    "999px",

                                  fontSize:
                                    "10px",

                                  opacity:
                                    0.85,
                                }}
                              >

                                <span
                                  style={{
                                    width:
                                      "7px",

                                    height:
                                      "7px",

                                    borderRadius:
                                      "50%",

                                    background:
                                      getEdgeColor(
                                        type as GraphEdge["type"]
                                      ),
                                  }}
                                />


                                {
                                  label
                                }

                              </span>

                            )
                          )
                        }

                      </div>


                      <svg
                        viewBox="0 0 900 580"
                        style={{
                          width:
                            "100%",

                          height:
                            "580px",
                        }}
                      >

                        {
                          graph.edges.map(
                            (edge) => {

                              const source =
                                graphPositions.get(
                                  edge.source
                                );


                              const target =
                                graphPositions.get(
                                  edge.target
                                );


                              if (
                                !source
                                ||
                                !target
                              ) {

                                return null;
                              }


                              const selected =
                                selectedGraphEdge
                                  ?.id
                                === edge.id;


                              const correlation =
                                edge.type
                                !== "CONTAINS";


                              const midpointX =
                                (
                                  source.x
                                  +
                                  target.x
                                )
                                /
                                2;


                              const midpointY =
                                (
                                  source.y
                                  +
                                  target.y
                                )
                                /
                                2;


                              return (

                                <g
                                  key={
                                    edge.id
                                  }
                                >

                                  <line
                                    x1={
                                      source.x
                                    }
                                    y1={
                                      source.y
                                    }
                                    x2={
                                      target.x
                                    }
                                    y2={
                                      target.y
                                    }
                                    stroke={
                                      getEdgeColor(
                                        edge.type
                                      )
                                    }
                                    strokeOpacity={
                                      edge.type
                                      === "CONTAINS"
                                        ? 0.22
                                        : selected
                                          ? 1
                                          : 0.72
                                    }
                                    strokeWidth={
                                      selected
                                        ? 4
                                        : correlation
                                          ? 2.2
                                          : 1
                                    }
                                  />


                                  {
                                    correlation
                                    &&
                                    (

                                      <line
                                        x1={
                                          source.x
                                        }
                                        y1={
                                          source.y
                                        }
                                        x2={
                                          target.x
                                        }
                                        y2={
                                          target.y
                                        }
                                        stroke="transparent"
                                        strokeWidth="14"
                                        style={{
                                          cursor:
                                            "pointer",
                                        }}
                                        onClick={() => {

                                          setSelectedGraphEdge(
                                            edge
                                          );

                                          setSelectedGraphNode(
                                            null
                                          );

                                          setSelectedGraphCluster(
                                            null
                                          );
                                        }}
                                      />

                                    )
                                  }


                                  {
                                    correlation
                                    &&
                                    (
                                      selected
                                      ||
                                      edge.strength
                                      >= 80
                                    )
                                    &&
                                    (

                                      <text
                                        x={
                                          midpointX
                                        }
                                        y={
                                          midpointY - 7
                                        }
                                        textAnchor="middle"
                                        fill={
                                          getEdgeColor(
                                            edge.type
                                          )
                                        }
                                        fontSize="8"
                                      >
                                        {
                                          edge.type
                                            .replace(
                                              /_/g,
                                              " "
                                            )
                                        }
                                      </text>

                                    )
                                  }

                                </g>

                              );
                            }
                          )
                        }


                        {
                          graph.nodes.map(
                            (node) => {

                              const point =
                                graphPositions.get(
                                  node.id
                                );


                              if (!point) {

                                return null;
                              }


                              const selected =
                                selectedGraphNode
                                  ?.id
                                === node.id;


                              return (

                                <g
                                  key={
                                    node.id
                                  }
                                  onClick={() => {

                                    setSelectedGraphNode(
                                      node
                                    );

                                    setSelectedGraphEdge(
                                      null
                                    );

                                    setSelectedGraphCluster(
                                      null
                                    );
                                  }}
                                  style={{
                                    cursor:
                                      "pointer",
                                  }}
                                >

                                  {
                                    selected
                                    &&
                                    (

                                      <circle
                                        cx={
                                          point.x
                                        }
                                        cy={
                                          point.y
                                        }
                                        r={
                                          node.type
                                          === "case"
                                            ? 53
                                            : 42
                                        }
                                        fill="transparent"
                                        stroke={
                                          getNodeColor(
                                            node
                                          )
                                        }
                                        strokeOpacity="0.25"
                                        strokeWidth="8"
                                      />

                                    )
                                  }


                                  <circle
                                    cx={
                                      point.x
                                    }
                                    cy={
                                      point.y
                                    }
                                    r={
                                      node.type
                                      === "case"
                                        ? 45
                                        : 34
                                    }
                                    fill="#101923"
                                    stroke={
                                      getNodeColor(
                                        node
                                      )
                                    }
                                    strokeWidth={
                                      selected
                                        ? 3
                                        : 2
                                    }
                                  />


                                  <text
                                    x={
                                      point.x
                                    }
                                    y={
                                      point.y - 3
                                    }
                                    textAnchor="middle"
                                    fill="#e8f2fc"
                                    fontSize="9"
                                    fontWeight="700"
                                  >
                                    {
                                      shortLabel(
                                        node.label,
                                        14
                                      )
                                    }
                                  </text>


                                  <text
                                    x={
                                      point.x
                                    }
                                    y={
                                      point.y + 11
                                    }
                                    textAnchor="middle"
                                    fill="#8797a8"
                                    fontSize="7"
                                  >
                                    {
                                      node.subtitle
                                    }
                                  </text>


                                  {
                                    node.risk
                                    !== null
                                    &&
                                    node.risk
                                    !== undefined
                                    &&
                                    (

                                      <text
                                        x={
                                          point.x
                                        }
                                        y={
                                          point.y + 48
                                        }
                                        textAnchor="middle"
                                        fill={
                                          getRiskColor(
                                            node.risk_level
                                            ??
                                            null
                                          )
                                        }
                                        fontSize="8"
                                        fontWeight="700"
                                      >
                                        {
                                          node.risk
                                        }% RISK
                                      </text>

                                    )
                                  }

                                </g>

                              );
                            }
                          )
                        }

                      </svg>

                    </div>


                    {
                      graph.clusters.length > 0
                      &&
                      (

                        <div
                          style={{
                            marginTop:
                              "18px",

                            border:
                              "1px solid var(--border)",

                            borderRadius:
                              "18px",

                            background:
                              "var(--panel)",

                            padding:
                              "18px",
                          }}
                        >

                          <span className="eyebrow">
                            CORRELATION CLUSTERS
                          </span>


                          <div
                            style={{
                              display:
                                "grid",

                              gridTemplateColumns:
                                "repeat(auto-fit, minmax(230px, 1fr))",

                              gap:
                                "12px",

                              marginTop:
                                "12px",
                            }}
                          >

                            {
                              graph.clusters.map(
                                (cluster) => (

                                  <button
                                    type="button"
                                    key={
                                      cluster.cluster_id
                                    }
                                    onClick={() => {

                                      setSelectedGraphCluster(
                                        cluster
                                      );

                                      setSelectedGraphNode(
                                        null
                                      );

                                      setSelectedGraphEdge(
                                        null
                                      );
                                    }}
                                    style={{
                                      textAlign:
                                        "left",

                                      border:
                                        selectedGraphCluster
                                          ?.cluster_id
                                        === cluster.cluster_id
                                          ? "1px solid rgba(127,198,255,0.6)"
                                          : "1px solid var(--border)",

                                      borderRadius:
                                        "14px",

                                      background:
                                        selectedGraphCluster
                                          ?.cluster_id
                                        === cluster.cluster_id
                                          ? "rgba(127,198,255,0.08)"
                                          : "rgba(255,255,255,0.025)",

                                      padding:
                                        "14px",

                                      cursor:
                                        "pointer",
                                    }}
                                  >

                                    <span className="eyebrow">
                                      {
                                        cluster.cluster_id
                                      }
                                    </span>


                                    <strong
                                      style={{
                                        display:
                                          "block",

                                        marginTop:
                                          "7px",

                                        fontSize:
                                          "20px",
                                      }}
                                    >
                                      {
                                        cluster.member_count
                                      }
                                      {" "}
                                      artifacts
                                    </strong>


                                    <p
                                      style={{
                                        marginTop:
                                          "7px",

                                        fontSize:
                                          "12px",

                                        opacity:
                                          0.7,
                                      }}
                                    >
                                      {
                                        cluster.relationship_count
                                      }
                                      {" relationships · "}
                                      {
                                        cluster.average_strength
                                      }
                                      {"% avg strength"}
                                    </p>

                                  </button>

                                )
                              )
                            }

                          </div>

                        </div>

                      )
                    }

                  </div>


                  <aside className="inspectorPanel">

                    {
                      selectedGraphEdge
                      &&
                      (

                        <>

                          <span className="eyebrow">
                            CORRELATION
                          </span>


                          <h3
                            style={{
                              marginTop:
                                "8px",
                            }}
                          >
                            {
                              selectedGraphEdge
                                .type
                                .replace(
                                  /_/g,
                                  " "
                                )
                            }
                          </h3>


                          <div
                            className="integrityCard"
                            style={{
                              marginTop:
                                "16px",

                              borderColor:
                                getEdgeColor(
                                  selectedGraphEdge
                                    .type
                                ),
                            }}
                          >

                            <div>

                              <span className="eyebrow">
                                RELATIONSHIP STRENGTH
                              </span>


                              <strong
                                style={{
                                  fontSize:
                                    "28px",

                                  color:
                                    getEdgeColor(
                                      selectedGraphEdge
                                        .type
                                    ),
                                }}
                              >
                                {
                                  selectedGraphEdge
                                    .strength
                                }%
                              </strong>


                              <p>
                                {
                                  selectedGraphEdge
                                    .level
                                }
                              </p>

                            </div>

                          </div>


                          <div className="inspectorHint">

                            <span className="eyebrow">
                              WHY CONNECTED
                            </span>


                            <p
                              style={{
                                marginTop:
                                  "8px",

                                lineHeight:
                                  "1.6",
                              }}
                            >
                              {
                                selectedGraphEdge
                                  .reason
                                ??
                                selectedGraphEdge
                                  .label
                              }
                            </p>

                          </div>


                          {
                            selectedGraphEdge
                              .indicator_type
                            &&
                            (

                              <div
                                className="hashItem"
                                style={{
                                  marginTop:
                                    "16px",
                                }}
                              >

                                <span>
                                  {
                                    selectedGraphEdge
                                      .indicator_type
                                  }
                                </span>


                                <code>
                                  {
                                    selectedGraphEdge
                                      .indicator_value
                                  }
                                </code>

                              </div>

                            )
                          }


                          <div
                            style={{
                              marginTop:
                                "18px",
                            }}
                          >

                            <span className="eyebrow">
                              CONNECTED ARTIFACTS
                            </span>


                            {
                              [
                                selectedGraphEdge.source,
                                selectedGraphEdge.target,
                              ]
                              .map(
                                (
                                  nodeId
                                ) => {

                                  const node =
                                    graph.nodes.find(
                                      (item) =>
                                        item.id
                                        === nodeId
                                    );


                                  if (
                                    !node
                                    ||
                                    node.type
                                    !== "evidence"
                                    ||
                                    !node.evidence_id
                                  ) {

                                    return null;
                                  }


                                  return (

                                    <button
                                      key={
                                        node.id
                                      }
                                      type="button"
                                      onClick={() =>
                                        reviewEvidence(
                                          node.evidence_id!
                                        )
                                      }
                                      style={{
                                        display:
                                          "block",

                                        width:
                                          "100%",

                                        textAlign:
                                          "left",

                                        marginTop:
                                          "8px",

                                        padding:
                                          "11px",

                                        border:
                                          "1px solid var(--border)",

                                        borderRadius:
                                          "11px",

                                        background:
                                          "rgba(255,255,255,0.025)",

                                        cursor:
                                          "pointer",
                                      }}
                                    >

                                      <strong>
                                        {
                                          node.subtitle
                                        }
                                      </strong>


                                      <span
                                        style={{
                                          display:
                                            "block",

                                          marginTop:
                                            "3px",

                                          fontSize:
                                            "11px",

                                          opacity:
                                            0.7,
                                        }}
                                      >
                                        {
                                          node.label
                                        }
                                      </span>

                                    </button>

                                  );
                                }
                              )
                            }

                          </div>

                        </>

                      )
                    }


                    {
                      !selectedGraphEdge
                      &&
                      selectedGraphCluster
                      &&
                      (

                        <>

                          <span className="eyebrow">
                            CORRELATION CLUSTER
                          </span>


                          <h3
                            style={{
                              marginTop:
                                "8px",
                            }}
                          >
                            {
                              selectedGraphCluster
                                .cluster_id
                            }
                          </h3>


                          <div className="inspectorGrid">

                            <div>

                              <span>
                                ARTIFACTS
                              </span>

                              <strong>
                                {
                                  selectedGraphCluster
                                    .member_count
                                }
                              </strong>

                            </div>


                            <div>

                              <span>
                                RELATIONS
                              </span>

                              <strong>
                                {
                                  selectedGraphCluster
                                    .relationship_count
                                }
                              </strong>

                            </div>


                            <div>

                              <span>
                                AVG STRENGTH
                              </span>

                              <strong>
                                {
                                  selectedGraphCluster
                                    .average_strength
                                }%
                              </strong>

                            </div>


                            <div>

                              <span>
                                MAX STRENGTH
                              </span>

                              <strong>
                                {
                                  selectedGraphCluster
                                    .maximum_strength
                                }%
                              </strong>

                            </div>

                          </div>


                          <div
                            style={{
                              marginTop:
                                "16px",
                            }}
                          >

                            <span className="eyebrow">
                              RELATION TYPES
                            </span>


                            <p
                              style={{
                                marginTop:
                                  "8px",

                                lineHeight:
                                  "1.6",
                              }}
                            >
                              {
                                selectedGraphCluster
                                  .relation_types
                                  .join(
                                    ", "
                                  )
                              }
                            </p>

                          </div>


                          <div
                            style={{
                              marginTop:
                                "18px",
                            }}
                          >

                            <span className="eyebrow">
                              CLUSTER MEMBERS
                            </span>


                            {
                              selectedGraphCluster
                                .members
                                .map(
                                  (member) => (

                                    <button
                                      type="button"
                                      key={
                                        member.evidence_id
                                      }
                                      onClick={() =>
                                        reviewEvidence(
                                          member.evidence_id
                                        )
                                      }
                                      style={{
                                        display:
                                          "block",

                                        width:
                                          "100%",

                                        textAlign:
                                          "left",

                                        marginTop:
                                          "8px",

                                        padding:
                                          "11px",

                                        border:
                                          "1px solid var(--border)",

                                        borderRadius:
                                          "11px",

                                        background:
                                          "rgba(255,255,255,0.025)",

                                        cursor:
                                          "pointer",
                                      }}
                                    >

                                      <strong>
                                        {
                                          member.evidence_code
                                        }
                                      </strong>


                                      <span
                                        style={{
                                          display:
                                            "block",

                                          marginTop:
                                            "3px",

                                          fontSize:
                                            "11px",

                                          opacity:
                                            0.7,
                                        }}
                                      >
                                        {
                                          member.filename
                                        }
                                      </span>

                                    </button>

                                  )
                                )
                            }

                          </div>

                        </>

                      )
                    }


                    {
                      !selectedGraphEdge
                      &&
                      !selectedGraphCluster
                      &&
                      selectedGraphNode
                      &&
                      (

                        <>

                          <span className="eyebrow">
                            GRAPH NODE
                          </span>


                          <h3
                            style={{
                              marginTop:
                                "8px",
                            }}
                          >
                            {
                              selectedGraphNode
                                .label
                            }
                          </h3>


                          <span className="artifactCode">
                            {
                              selectedGraphNode
                                .subtitle
                            }
                          </span>


                          {
                            selectedGraphNode
                              .type
                            === "evidence"
                            &&
                            (

                              <>

                                <div
                                  className="inspectorGrid"
                                  style={{
                                    marginTop:
                                      "16px",
                                  }}
                                >

                                  <div>

                                    <span>
                                      TYPE
                                    </span>

                                    <strong>
                                      {
                                        selectedGraphNode
                                          .extension
                                        ??
                                        "—"
                                      }
                                    </strong>

                                  </div>


                                  <div>

                                    <span>
                                      RISK
                                    </span>

                                    <strong
                                      style={{
                                        color:
                                          getRiskColor(
                                            selectedGraphNode
                                              .risk_level
                                            ??
                                            null
                                          ),
                                      }}
                                    >
                                      {
                                        selectedGraphNode
                                          .risk
                                        !== null
                                        &&
                                        selectedGraphNode
                                          .risk
                                        !== undefined
                                          ? `${selectedGraphNode.risk}%`
                                          : "UNASSESSED"
                                      }
                                    </strong>

                                  </div>


                                  <div>

                                    <span>
                                      INTEGRITY
                                    </span>

                                    <strong>
                                      {
                                        selectedGraphNode
                                          .integrity
                                        ??
                                        "—"
                                      }
                                    </strong>

                                  </div>


                                  <div>

                                    <span>
                                      ENTROPY
                                    </span>

                                    <strong>
                                      {
                                        selectedGraphNode
                                          .entropy
                                        ??
                                        "—"
                                      }
                                    </strong>

                                  </div>

                                </div>


                                {
                                  selectedGraphNode
                                    .analyzer
                                  &&
                                  (

                                    <div
                                      className="inspectorHint"
                                      style={{
                                        marginTop:
                                          "16px",
                                      }}
                                    >

                                      <span className="eyebrow">
                                        RISK SOURCE
                                      </span>


                                      <p
                                        style={{
                                          marginTop:
                                            "8px",
                                        }}
                                      >
                                        {
                                          selectedGraphNode
                                            .analyzer
                                        }
                                      </p>

                                    </div>

                                  )
                                }


                                {
                                  selectedGraphNode
                                    .evidence_id
                                  &&
                                  (

                                    <button
                                      type="button"
                                      style={{
                                        marginTop:
                                          "18px",
                                      }}
                                      onClick={() =>
                                        reviewEvidence(
                                          selectedGraphNode
                                            .evidence_id!
                                        )
                                      }
                                    >
                                      Open Evidence
                                    </button>

                                  )
                                }

                              </>

                            )
                          }

                        </>

                      )
                    }


                    <div
                      className="inspectorHint"
                      style={{
                        marginTop:
                          "18px",
                      }}
                    >

                      <span className="eyebrow">
                        FORENSIC LIMITATION
                      </span>


                      <p
                        style={{
                          marginTop:
                            "8px",

                          lineHeight:
                            "1.6",
                        }}
                      >
                        {
                          graph.disclaimer
                        }
                      </p>

                    </div>

                  </aside>

                </section>

              </>

            )
          }


          {/* =================================================
              AI ANALYST
          ================================================= */}


          {
            activeTab === "analyst"
            &&
            (

              <section
                style={{
                  display:
                    "grid",

                  gridTemplateColumns:
                    "minmax(300px, 340px) minmax(0, 1fr)",

                  gap:
                    "18px",

                  alignItems:
                    "stretch",

                  minWidth:
                    0,
                }}
              >

                <aside
                  className="inspectorPanel"
                  style={{
                    minWidth: 0,
                    overflow: "hidden",
                    alignSelf: "stretch",
                  }}
                >

                  <span className="eyebrow">
                    CASE BRIEF
                  </span>


                  <h3
                    style={{
                      marginTop:
                        "8px",
                    }}
                  >
                    {
                      analystBrief
                        ?.case
                        .name
                      ??
                      forensicCase.name
                    }
                  </h3>


                  {
                    analystBrief
                    &&
                    (

                      <>

                        <div
                          className="integrityCard"
                          style={{
                            marginTop:
                              "16px",
                          }}
                        >

                          <div>

                            <span className="eyebrow">
                              CURRENT STATE
                            </span>


                            <strong>
                              {
                                analystBrief
                                  .brief
                                  .headline
                              }
                            </strong>

                          </div>

                        </div>


                        <div
                          style={{
                            marginTop:
                              "16px",
                          }}
                        >

                          <span className="eyebrow">
                            OBSERVATIONS
                          </span>


                          {
                            analystBrief
                              .brief
                              .observations
                              .map(
                                (
                                  observation,
                                  index
                                ) => (

                                  <div
                                    className="inspectorHint"
                                    key={
                                      `${observation}-${index}`
                                    }
                                    style={{
                                      marginTop:
                                        "8px",
                                    }}
                                  >

                                    <strong>
                                      {
                                        observation
                                      }
                                    </strong>

                                  </div>

                                )
                              )
                          }

                        </div>


                        {
                          analystBrief
                            .priority_queue
                            .length > 0
                          &&
                          (

                            <div
                              style={{
                                marginTop:
                                  "18px",
                              }}
                            >

                              <span className="eyebrow">
                                TOP PRIORITY
                              </span>


                              {
                                analystBrief
                                  .priority_queue
                                  .slice(
                                    0,
                                    3
                                  )
                                  .map(
                                    (
                                      item,
                                      index
                                    ) => (

                                      <button
                                        key={
                                          item.evidence_id
                                        }
                                        type="button"
                                        onClick={() =>
                                          reviewEvidence(
                                            item.evidence_id
                                          )
                                        }
                                        style={{
                                          width:
                                            "100%",

                                          minWidth:
                                            0,

                                          display:
                                            "block",

                                          textAlign:
                                            "left",

                                          whiteSpace:
                                            "normal",

                                          overflow:
                                            "hidden",

                                          marginTop:
                                            "8px",

                                          padding:
                                            "12px",

                                          border:
                                            "1px solid var(--border)",

                                          borderRadius:
                                            "11px",

                                          background:
                                            "rgba(255,255,255,0.025)",
                                        }}
                                      >

                                        <span
                                          className="eyebrow"
                                          style={{
                                            display: "block",
                                            marginBottom: "6px",
                                          }}
                                        >
                                          #
                                          {
                                            index + 1
                                          }
                                          {" · "}
                                          {
                                            item.priority_score
                                          }%
                                        </span>


                                        <strong
                                          style={{
                                            display:
                                              "block",

                                            marginTop:
                                              "5px",

                                            overflowWrap:
                                              "anywhere",

                                            color:
                                              "#dcecf8",
                                          }}
                                        >
                                          {
                                            item.evidence_code
                                          }
                                        </strong>


                                        <span
                                          style={{
                                            display:
                                              "block",

                                            marginTop:
                                              "3px",

                                            fontSize:
                                              "11px",

                                            opacity:
                                              0.68,

                                            width:
                                              "100%",

                                            overflow:
                                              "hidden",

                                            textOverflow:
                                              "ellipsis",

                                            whiteSpace:
                                              "nowrap",
                                          }}
                                        >
                                          {
                                            item.filename
                                          }
                                        </span>

                                      </button>

                                    )
                                  )
                              }

                            </div>

                          )
                        }

                      </>

                    )
                  }

                </aside>


                <section
                  style={{
                    border:
                      "1px solid var(--border)",

                    borderRadius:
                      "18px",

                    background:
                      "var(--panel)",

                    overflow:
                      "hidden",

                    minWidth:
                      0,

                    minHeight:
                      "560px",

                    display:
                      "flex",

                    flexDirection:
                      "column",
                  }}
                >

                  <div
                    className="sectionHeader"
                    style={{
                      padding:
                        "18px 20px",
                    }}
                  >

                    <div>

                      <span className="eyebrow">
                        GEMINI-POWERED
                      </span>


                      <h2>
                        AI Forensic Analyst
                      </h2>

                    </div>


                    <span
                      style={{
                        color:
                          "#70e5b5",

                        fontSize:
                          "11px",

                        fontWeight:
                          700,

                        whiteSpace:
                          "nowrap",

                        marginLeft:
                          "12px",
                      }}
                    >
                      ● CASE + GRAPH GROUNDED
                    </span>

                  </div>


                  {
                    analystMessages.length
                    === 0
                    &&
                    (

                      <div
                        style={{
                          padding:
                            "20px",
                        }}
                      >

                        <span className="eyebrow">
                          SUGGESTED QUESTIONS
                        </span>


                        <div
                          style={{
                            display:
                              "grid",

                            gridTemplateColumns:
                              "repeat(auto-fit, minmax(250px, 1fr))",

                            gap:
                              "10px",

                            marginTop:
                              "12px",
                          }}
                        >

                          {
                            [
                              "What should I investigate first?",
                              "What evidence is correlated?",
                              "What connects the two sample.txt artifacts?",
                              "Which correlation cluster deserves attention?",
                              "Are multiple artifacts pointing to the same infrastructure?",
                              "Does any high-risk evidence share indicators with another file?",
                            ]
                            .map(
                              (question) => (

                                <button
                                  key={
                                    question
                                  }
                                  type="button"
                                  disabled={
                                    analystLoading
                                  }
                                  onClick={() =>
                                    void handleAskAnalyst(
                                      question
                                    )
                                  }
                                  style={{
                                    width:
                                      "100%",

                                    minHeight:
                                      "54px",

                                    display:
                                      "block",

                                    textAlign:
                                      "left",

                                    whiteSpace:
                                      "normal",

                                    padding:
                                      "13px 14px",

                                    border:
                                      "1px solid var(--border)",

                                    borderRadius:
                                      "12px",

                                    background:
                                      "rgba(255,255,255,0.025)",

                                    lineHeight:
                                      "1.45",
                                  }}
                                >
                                  {
                                    question
                                  }
                                </button>

                              )
                            )
                          }

                        </div>

                      </div>

                    )
                  }


                  <div
                    style={{
                      padding:
                        "20px",

                      flex:
                        1,

                      minHeight:
                        "170px",

                      maxHeight:
                        "520px",

                      overflowY:
                        "auto",

                      display:
                        "flex",

                      flexDirection:
                        "column",

                      gap:
                        "14px",
                    }}
                  >

                    {
                      analystMessages.length === 0
                      &&
                      !analystLoading
                      &&
                      (

                        <div
                          style={{
                            flex: 1,
                            minHeight: "120px",
                            display: "grid",
                            placeItems: "center",
                            textAlign: "center",
                            padding: "18px",
                            border: "1px dashed rgba(155,220,255,0.12)",
                            borderRadius: "14px",
                            background: "rgba(155,220,255,0.018)",
                          }}
                        >
                          <div style={{ maxWidth: "520px" }}>
                            <span className="eyebrow">GROUNDING READY</span>
                            <strong
                              style={{
                                display: "block",
                                marginTop: "8px",
                                fontSize: "14px",
                              }}
                            >
                              Ask SYNAPSE about this investigation
                            </strong>
                            <p
                              style={{
                                marginTop: "6px",
                                fontSize: "11px",
                                lineHeight: "1.6",
                                opacity: 0.62,
                              }}
                            >
                              Answers are grounded in the current case, forensic results,
                              coverage, blind spots and deterministic evidence graph.
                            </p>
                          </div>
                        </div>

                      )
                    }


                    {
                      analystMessages.map(
                        (message) => (

                          <div
                            key={
                              message.id
                            }
                            style={{
                              padding:
                                "14px 16px",

                              border:
                                "1px solid var(--border)",

                              borderRadius:
                                "14px",

                              background:
                                message.role
                                === "user"
                                  ? "rgba(127,198,255,0.08)"
                                  : "rgba(255,255,255,0.025)",

                              alignSelf:
                                message.role
                                === "user"
                                  ? "flex-end"
                                  : "stretch",

                              width:
                                message.role
                                === "user"
                                  ? "min(78%,620px)"
                                  : "100%",

                              minWidth:
                                0,

                              overflow:
                                "hidden",
                            }}
                          >

                            <span className="eyebrow">
                              {
                                message.role
                                === "user"
                                  ? "INVESTIGATOR"
                                  : "SYNAPSE AI"
                              }
                            </span>


                            <p
                              style={{
                                marginTop:
                                  "8px",

                                lineHeight:
                                  "1.7",

                                whiteSpace:
                                  "pre-wrap",

                                overflowWrap:
                                  "anywhere",
                              }}
                            >
                              {
                                message.text
                              }
                            </p>


                            {
                              message.response
                              &&
                              (

                                <>

                                  {
                                    message.response
                                      .evidence_references
                                      .length > 0
                                    &&
                                    (

                                      <div
                                        style={{
                                          marginTop:
                                            "14px",
                                        }}
                                      >

                                        <span className="eyebrow">
                                          REFERENCED EVIDENCE
                                        </span>


                                        <div
                                          style={{
                                            display:
                                              "flex",

                                            flexWrap:
                                              "wrap",

                                            gap:
                                              "7px",

                                            marginTop:
                                              "8px",
                                          }}
                                        >

                                          {
                                            message.response
                                              .evidence_references
                                              .map(
                                                (
                                                  reference
                                                ) => (

                                                  <button
                                                    type="button"
                                                    key={
                                                      reference
                                                    }
                                                    onClick={() =>
                                                      openEvidenceByCode(
                                                        reference
                                                      )
                                                    }
                                                    style={{
                                                      padding:
                                                        "7px 10px",

                                                      border:
                                                        "1px solid rgba(127,198,255,0.35)",

                                                      borderRadius:
                                                        "999px",

                                                      background:
                                                        "rgba(127,198,255,0.07)",

                                                      color:
                                                        "#9dd4ff",

                                                      fontSize:
                                                        "10px",

                                                      fontWeight:
                                                        700,
                                                    }}
                                                  >
                                                    {
                                                      reference
                                                    }
                                                  </button>

                                                )
                                              )
                                          }

                                        </div>

                                      </div>

                                    )
                                  }


                                  <AnalystCorrelationCards
                                    graph={
                                      graph
                                    }
                                    evidenceReferences={
                                      message.response
                                        .evidence_references
                                    }
                                    onOpenEvidence={
                                      openEvidenceByCode
                                    }
                                    onOpenEdge={
                                      openGraphEdge
                                    }
                                    onOpenCluster={
                                      openGraphCluster
                                    }
                                  />


                                  {
                                    message.response
                                      .recommended_actions
                                      .length > 0
                                    &&
                                    (

                                      <div
                                        style={{
                                          marginTop:
                                            "16px",
                                        }}
                                      >

                                        <span className="eyebrow">
                                          RECOMMENDED ACTIONS
                                        </span>


                                        {
                                          message.response
                                            .recommended_actions
                                            .map(
                                              (
                                                action,
                                                index
                                              ) => (

                                                <div
                                                  className="inspectorHint"
                                                  key={
                                                    `${action}-${index}`
                                                  }
                                                  style={{
                                                    marginTop:
                                                      "7px",
                                                  }}
                                                >

                                                  <strong>
                                                    →
                                                    {" "}
                                                    {
                                                      action
                                                    }
                                                  </strong>

                                                </div>

                                              )
                                            )
                                        }

                                      </div>

                                    )
                                  }


                                  {
                                    message.response
                                      .limitations
                                      .length > 0
                                    &&
                                    (

                                      <div
                                        style={{
                                          marginTop:
                                            "16px",
                                        }}
                                      >

                                        <span className="eyebrow">
                                          LIMITATIONS
                                        </span>


                                        {
                                          message.response
                                            .limitations
                                            .map(
                                              (
                                                limitation,
                                                index
                                              ) => (

                                                <p
                                                  key={
                                                    `${limitation}-${index}`
                                                  }
                                                  style={{
                                                    marginTop:
                                                      "7px",

                                                    fontSize:
                                                      "11px",

                                                    lineHeight:
                                                      "1.5",

                                                    opacity:
                                                      0.68,
                                                  }}
                                                >
                                                  •{" "}
                                                  {
                                                    limitation
                                                  }
                                                </p>

                                              )
                                            )
                                        }

                                      </div>

                                    )
                                  }


                                  <div
                                    style={{
                                      display:
                                        "flex",

                                      justifyContent:
                                        "space-between",

                                      gap:
                                        "12px",

                                      marginTop:
                                        "16px",

                                      paddingTop:
                                        "10px",

                                      borderTop:
                                        "1px solid var(--border)",

                                      fontSize:
                                        "9px",

                                      opacity:
                                        0.5,
                                    }}
                                  >

                                    <span>
                                      {
                                        message.response
                                          .model_name
                                      }
                                    </span>


                                    <span>
                                      {
                                        message.response
                                          .grounded
                                          ? "GROUNDED RESPONSE"
                                          : "UNGROUNDED"
                                      }
                                    </span>

                                  </div>

                                </>

                              )
                            }

                          </div>

                        )
                      )
                    }


                    {
                      analystLoading
                      &&
                      (

                        <div className="inspectorHint">

                          <span className="eyebrow">
                            SYNAPSE AI
                          </span>


                          <p
                            style={{
                              marginTop:
                                "7px",
                            }}
                          >
                            Analyzing grounded case and
                            deterministic correlation context...
                          </p>

                        </div>

                      )
                    }

                  </div>


                  <form
                    onSubmit={
                      handleAnalystSubmit
                    }
                    style={{
                      display:
                        "grid",

                      gridTemplateColumns:
                        "minmax(0, 1fr) auto",

                      gap:
                        "10px",

                      alignItems:
                        "stretch",

                      padding:
                        "16px 20px",

                      borderTop:
                        "1px solid var(--border)",
                    }}
                  >

                    <textarea
                      value={
                        analystInput
                      }
                      onChange={
                        (
                          event
                        ) =>
                          setAnalystInput(
                            event.target.value
                          )
                      }
                      onKeyDown={(event) => {
                        if (
                          event.key === "Enter"
                          &&
                          !event.shiftKey
                        ) {
                          event.preventDefault();

                          if (
                            !analystLoading
                            &&
                            analystInput.trim().length >= 3
                          ) {
                            void handleAskAnalyst();
                          }
                        }
                      }}
                      disabled={
                        analystLoading
                      }
                      rows={2}
                      placeholder="Ask about evidence, risk, blind spots, IOCs, clusters or correlations..."
                      style={{
                        flex:
                          1,

                        resize:
                          "none",

                        minWidth:
                          0,

                        minHeight:
                          "58px",

                        maxHeight:
                          "130px",

                        border:
                          "1px solid var(--border)",

                        borderRadius:
                          "12px",

                        padding:
                          "12px",

                        background:
                          "rgba(255,255,255,0.025)",

                        color:
                          "inherit",

                        font:
                          "inherit",
                      }}
                    />


                    <button
                      type="submit"
                      style={{
                        minWidth: "92px",
                        paddingInline: "18px",
                      }}
                      disabled={
                        analystLoading
                        ||
                        analystInput
                          .trim()
                          .length < 3
                      }
                    >
                      {
                        analystLoading
                          ? "Thinking..."
                          : "Ask"
                      }
                    </button>

                  </form>

                </section>

              </section>

            )
          }


          {/* =================================================
              BLIND SPOTS
          ================================================= */}


          {
            activeTab === "blindspots"
            &&
            blindSpotReport
            &&
            (

              <section className="evidenceWorkspace">

                <div className="evidencePanel">

                  <div className="sectionHeader">

                    <div>

                      <span className="eyebrow">
                        EVIDENCE COVERAGE ASSURANCE
                      </span>


                      <h2>
                        Priority Blind Spots
                      </h2>

                    </div>


                    <button
                      type="button"
                      disabled={
                        blindSpotLoading
                      }
                      onClick={() =>
                        void handleBlindSpotRecalculate()
                      }
                    >
                      {
                        blindSpotLoading
                          ? "Recalculating..."
                          : "Recalculate"
                      }
                    </button>

                  </div>


                  <div className="evidenceList">

                    {
                      blindSpotReport
                        .blind_spots
                        .map(
                          (
                            item,
                            index
                          ) => (

                            <button
                              type="button"
                              key={
                                item.evidence_id
                              }
                              className={
                                `evidenceRow ${
                                  selectedBlindSpot
                                    ?.evidence_id
                                  === item.evidence_id
                                    ? "selected"
                                    : ""
                                }`
                              }
                              onClick={() =>
                                setSelectedBlindSpot(
                                  item
                                )
                              }
                            >

                              <div className="evidenceRowMain">

                                <strong>
                                  #
                                  {
                                    index + 1
                                  }
                                  {" "}
                                  {
                                    item.filename
                                  }
                                </strong>


                                <span>
                                  {
                                    item.evidence_code
                                  }
                                </span>

                              </div>


                              <div className="evidenceMeta">

                                <span>
                                  Risk{" "}
                                  {
                                    item.forensic_risk
                                  }%
                                </span>


                                <span>
                                  Coverage{" "}
                                  {
                                    item.coverage_score
                                  }%
                                </span>

                              </div>


                              <span
                                style={{
                                  color:
                                    getSeverityColor(
                                      item.severity
                                    ),

                                  fontWeight:
                                    800,
                                }}
                              >
                                {
                                  item.blind_spot_score
                                }%
                                {" · "}
                                {
                                  item.severity
                                }
                              </span>

                            </button>

                          )
                        )
                    }

                  </div>

                </div>


                <aside className="inspectorPanel">

                  {
                    selectedBlindSpot
                    &&
                    (

                      <>

                        <span className="eyebrow">
                          BLIND SPOT INSPECTOR
                        </span>


                        <h3
                          style={{
                            marginTop:
                              "8px",
                          }}
                        >
                          {
                            selectedBlindSpot
                              .filename
                          }
                        </h3>


                        <div className="integrityCard">

                          <div>

                            <strong
                              style={{
                                color:
                                  getSeverityColor(
                                    selectedBlindSpot
                                      .severity
                                  ),

                                fontSize:
                                  "28px",
                              }}
                            >
                              {
                                selectedBlindSpot
                                  .blind_spot_score
                              }%
                            </strong>


                            <p>
                              Risk{" "}
                              {
                                selectedBlindSpot
                                  .forensic_risk
                              }%
                              {" · "}
                              Coverage{" "}
                              {
                                selectedBlindSpot
                                  .coverage_score
                              }%
                            </p>

                          </div>


                          <button
                            type="button"
                            onClick={() =>
                              reviewEvidence(
                                selectedBlindSpot
                                  .evidence_id
                              )
                            }
                          >
                            Review Evidence
                          </button>

                        </div>


                        <CoverageBar
                          label="Focused Review"
                          value={
                            selectedBlindSpot
                              .review_components
                              .focused_duration
                          }
                          description="Focused review duration"
                        />


                        <CoverageBar
                          label="Views"
                          value={
                            selectedBlindSpot
                              .review_components
                              .views
                          }
                          description="Evidence access"
                        />


                        <CoverageBar
                          label="Revisits"
                          value={
                            selectedBlindSpot
                              .review_components
                              .revisits
                          }
                          description="Repeated review"
                        />


                        <CoverageBar
                          label="Visible Tab"
                          value={
                            selectedBlindSpot
                              .review_components
                              .visible_tab_ratio
                          }
                          description="Foreground review ratio"
                        />


                        <CoverageBar
                          label="Investigation Actions"
                          value={
                            selectedBlindSpot
                              .review_components
                              .investigation_actions
                          }
                          description="Triage + integrity"
                        />


                        <div
                          style={{
                            marginTop:
                              "16px",
                          }}
                        >

                          <span className="eyebrow">
                            WHY FLAGGED
                          </span>


                          {
                            selectedBlindSpot
                              .reasons
                              .map(
                                (
                                  reason,
                                  index
                                ) => (

                                  <div
                                    key={
                                      `${reason}-${index}`
                                    }
                                    className="inspectorHint"
                                    style={{
                                      marginTop:
                                        "7px",
                                    }}
                                  >
                                    {
                                      reason
                                    }
                                  </div>

                                )
                              )
                          }

                        </div>

                      </>

                    )
                  }

                </aside>

              </section>

            )
          }


          {/* =================================================
              COVERAGE
          ================================================= */}


          {
            activeTab === "coverage"
            &&
            coverageReport
            &&
            (

              <section className="evidenceWorkspace">

                <div className="evidencePanel">

                  <div className="sectionHeader">

                    <div>

                      <span className="eyebrow">
                        HUMAN-AWARE REVIEW
                      </span>


                      <h2>
                        Investigation Coverage
                      </h2>

                    </div>


                    <button
                      type="button"
                      onClick={() =>
                        void refreshCoverage()
                      }
                    >
                      Refresh
                    </button>

                  </div>


                  <div className="evidenceList">

                    {
                      coverageReport
                        .evidence_coverage
                        .map(
                          (item) => (

                            <button
                              type="button"
                              key={
                                item.evidence_id
                              }
                              className={
                                `evidenceRow ${
                                  selectedCoverage
                                    ?.evidence_id
                                  === item.evidence_id
                                    ? "selected"
                                    : ""
                                }`
                              }
                              onClick={() =>
                                setSelectedCoverage(
                                  item
                                )
                              }
                            >

                              <div className="evidenceRowMain">

                                <strong>
                                  {
                                    item.filename
                                  }
                                </strong>


                                <span>
                                  {
                                    item.evidence_code
                                  }
                                  {" · "}
                                  {
                                    item.coverage_level
                                  }
                                </span>

                              </div>


                              <div className="evidenceMeta">

                                <span>
                                  {
                                    item.forensic_risk
                                    !== null
                                      ? `${item.forensic_risk}% risk`
                                      : "Not triaged"
                                  }
                                </span>


                                <span>
                                  {
                                    item.attention
                                      .view_count
                                  } views
                                </span>

                              </div>


                              <strong
                                style={{
                                  color:
                                    getCoverageColor(
                                      item.coverage_score
                                    ),
                                }}
                              >
                                {
                                  item.coverage_score
                                }%
                              </strong>

                            </button>

                          )
                        )
                    }

                  </div>

                </div>


                <aside className="inspectorPanel">

                  {
                    selectedCoverage
                    &&
                    (

                      <>

                        <span className="eyebrow">
                          COVERAGE INSPECTOR
                        </span>


                        <h3
                          style={{
                            marginTop:
                              "8px",
                          }}
                        >
                          {
                            selectedCoverage
                              .filename
                          }
                        </h3>


                        <span className="artifactCode">
                          {
                            selectedCoverage
                              .evidence_code
                          }
                        </span>


                        <div className="integrityCard">

                          <div>

                            <strong
                              style={{
                                fontSize:
                                  "30px",

                                color:
                                  getCoverageColor(
                                    selectedCoverage
                                      .coverage_score
                                  ),
                              }}
                            >
                              {
                                selectedCoverage
                                  .coverage_score
                              }%
                            </strong>


                            <p>
                              {
                                selectedCoverage
                                  .coverage_level
                              }
                            </p>

                          </div>


                          <button
                            type="button"
                            onClick={() =>
                              reviewEvidence(
                                selectedCoverage
                                  .evidence_id
                              )
                            }
                          >
                            Review Evidence
                          </button>

                        </div>


                        <CoverageBar
                          label="Focused Review"
                          value={
                            selectedCoverage
                              .components
                              .focused_duration
                          }
                          description="Focused review duration"
                        />


                        <CoverageBar
                          label="Views"
                          value={
                            selectedCoverage
                              .components
                              .views
                          }
                          description="Evidence access count"
                        />


                        <CoverageBar
                          label="Revisits"
                          value={
                            selectedCoverage
                              .components
                              .revisits
                          }
                          description="Repeated review"
                        />


                        <CoverageBar
                          label="Visible Tab"
                          value={
                            selectedCoverage
                              .components
                              .visible_tab_ratio
                          }
                          description="Foreground review ratio"
                        />


                        <CoverageBar
                          label="Investigation Actions"
                          value={
                            selectedCoverage
                              .components
                              .investigation_actions
                          }
                          description="Triage and integrity verification"
                        />

                      </>

                    )
                  }

                </aside>

              </section>

            )
          }


          {/* =================================================
              INVESTIGATION TIMELINE + REPLAY
          ================================================= */}


          {
            activeTab === "timeline"
            &&
            (

              <InvestigationTimeline
                caseId={
                  caseId
                }
                onOpenEvidence={
                  reviewEvidence
                }
              />

            )
          }


          {/* =================================================
              FORENSIC REPORT
          ================================================= */}


          {
            activeTab === "report"
            &&
            (

              <ForensicReportDashboard
                caseId={
                  caseId
                }
                onOpenEvidence={
                  reviewEvidence
                }
                onOpenGraph={() =>
                  setActiveTab(
                    "graph"
                  )
                }
              />

            )
          }


          {/* =================================================
              CHAIN OF CUSTODY
          ================================================= */}


          {
            activeTab === "ledger"
            &&
            (

              <section className="ledgerPanel">

                <div className="sectionHeader">

                  <div>

                    <span className="eyebrow">
                      TAMPER-EVIDENT AUDIT
                    </span>


                    <h2>
                      Chain of Custody
                    </h2>

                  </div>

                </div>


                {
                  ledger.map(
                    (entry) => (

                      <article
                        className="ledgerEntry"
                        key={
                          entry.id
                        }
                      >

                        <div>

                          <strong>
                            {
                              entry.event_type
                            }
                          </strong>


                          <p>
                            {
                              entry.event_data
                            }
                          </p>

                        </div>


                        <div className="hashBlock">

                          <span>
                            PREVIOUS HASH
                          </span>


                          <code>
                            {
                              entry.previous_hash
                            }
                          </code>


                          <span>
                            CURRENT HASH
                          </span>


                          <code>
                            {
                              entry.current_hash
                            }
                          </code>

                        </div>

                      </article>

                    )
                  )
                }

              </section>

            )
          }

        </div>

      </section>

    </main>
  );
}
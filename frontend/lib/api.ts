import type {
  AnalystAnswerResponse,
  AnalystBriefResponse,
  ArtifactTriageResult,
  AttentionCaseSummary,
  AttentionUpdate,
  BlindSpotReport,
  CoverageReport,
  CreateCasePayload,
  Evidence,
  EvidenceAttention,
  EvidenceCoverageItem,
  EvidenceGraph,
  ForensicCase,
  LedgerEntry,
  MLExplanation,
  MLPrediction,
} from "./types";


const API_URL =
  process.env.NEXT_PUBLIC_API_URL ??
  "http://127.0.0.1:8000";


async function request<T>(
  path: string,
  options?: RequestInit
): Promise<T> {

  const response =
    await fetch(
      `${API_URL}${path}`,
      options
    );


  if (!response.ok) {

    let message =
      `Request failed with status ${response.status}.`;


    try {

      const data =
        await response.json();


      if (data.detail) {

        message =
          typeof data.detail === "string"
            ? data.detail
            : JSON.stringify(
                data.detail
              );
      }

    } catch {
      // Keep fallback.
    }


    throw new Error(
      message
    );
  }


  if (
    response.status === 204
  ) {

    return undefined as T;
  }


  return response.json() as Promise<T>;
}


/* ======================================================
   CASES
====================================================== */

export function getCases() {

  return request<ForensicCase[]>(
    "/api/cases"
  );
}


export function getCase(
  caseId: number
) {

  return request<ForensicCase>(
    `/api/cases/${caseId}`
  );
}


export function createCase(
  payload: CreateCasePayload
) {

  return request<ForensicCase>(
    "/api/cases",
    {
      method: "POST",

      headers: {
        "Content-Type":
          "application/json",
      },

      body:
        JSON.stringify(
          payload
        ),
    }
  );
}


export function deleteCase(
  caseId: number
) {

  return request<void>(
    `/api/cases/${caseId}`,
    {
      method: "DELETE",
    }
  );
}


/* ======================================================
   LEDGER
====================================================== */

export function getCaseLedger(
  caseId: number
) {

  return request<LedgerEntry[]>(
    `/api/cases/${caseId}/ledger`
  );
}


/* ======================================================
   EVIDENCE
====================================================== */

export function getCaseEvidence(
  caseId: number
) {

  return request<Evidence[]>(
    `/api/cases/${caseId}/evidence`
  );
}


export function uploadEvidence(
  caseId: number,
  file: File
) {

  const formData =
    new FormData();


  formData.append(
    "file",
    file
  );


  return request<Evidence>(
    `/api/cases/${caseId}/evidence`,
    {
      method: "POST",
      body: formData,
    }
  );
}


export function verifyEvidenceIntegrity(
  caseId: number,
  evidenceId: number
) {

  return request<Evidence>(
    `/api/cases/${caseId}/evidence/${evidenceId}/verify`,
    {
      method: "POST",
    }
  );
}


/* ======================================================
   PE MACHINE LEARNING
====================================================== */

export function runMLTriage(
  caseId: number,
  evidenceId: number
) {

  return request<MLPrediction>(
    `/api/ml/cases/${caseId}/evidence/${evidenceId}/predict`,
    {
      method: "POST",
    }
  );
}


export function getCasePredictions(
  caseId: number
) {

  return request<MLPrediction[]>(
    `/api/ml/cases/${caseId}/predictions`
  );
}


export function getMLExplanation(
  caseId: number,
  evidenceId: number
) {

  return request<MLExplanation>(
    `/api/ml/cases/${caseId}/evidence/${evidenceId}/explain`
  );
}


/* ======================================================
   MULTI-ARTIFACT TRIAGE
====================================================== */

export function runArtifactTriage(
  caseId: number,
  evidenceId: number
) {

  return request<ArtifactTriageResult>(
    `/api/triage/cases/${caseId}/evidence/${evidenceId}`,
    {
      method: "POST",
    }
  );
}


export function getCaseArtifactTriage(
  caseId: number
) {

  return request<ArtifactTriageResult[]>(
    `/api/triage/cases/${caseId}`
  );
}


/* ======================================================
   ATTENTION TELEMETRY
====================================================== */

export function recordEvidenceAttention(
  caseId: number,
  evidenceId: number,
  payload: AttentionUpdate
) {

  return request<EvidenceAttention>(
    `/api/attention/cases/${caseId}/evidence/${evidenceId}`,
    {
      method: "POST",

      headers: {
        "Content-Type":
          "application/json",
      },

      body:
        JSON.stringify(
          payload
        ),
    }
  );
}


export function getCaseAttention(
  caseId: number
) {

  return request<EvidenceAttention[]>(
    `/api/attention/cases/${caseId}`
  );
}


export function getAttentionSummary(
  caseId: number
) {

  return request<AttentionCaseSummary>(
    `/api/attention/cases/${caseId}/summary`
  );
}


/* ======================================================
   ADVANCED COVERAGE
====================================================== */

export function getCaseCoverage(
  caseId: number
) {

  return request<CoverageReport>(
    `/api/coverage/cases/${caseId}`
  );
}


export function getEvidenceCoverage(
  caseId: number,
  evidenceId: number
) {

  return request<EvidenceCoverageItem>(
    `/api/coverage/cases/${caseId}/evidence/${evidenceId}`
  );
}


/* ======================================================
   BLIND SPOTS
====================================================== */

export function getBlindSpots(
  caseId: number
) {

  return request<BlindSpotReport>(
    `/api/blind-spots/cases/${caseId}`
  );
}


export function recalculateBlindSpots(
  caseId: number
) {

  return request<BlindSpotReport>(
    `/api/blind-spots/cases/${caseId}/recalculate`,
    {
      method: "POST",
    }
  );
}


/* ======================================================
   AI FORENSIC ANALYST
====================================================== */

export function getAnalystBrief(
  caseId: number
) {

  return request<AnalystBriefResponse>(
    `/api/analyst/cases/${caseId}/brief`
  );
}


export function askAnalyst(
  caseId: number,
  question: string
) {

  return request<AnalystAnswerResponse>(
    `/api/analyst/cases/${caseId}/ask`,
    {
      method: "POST",

      headers: {
        "Content-Type":
          "application/json",
      },

      body:
        JSON.stringify({
          question,
        }),
    }
  );
}


/* ======================================================
   GRAPH
====================================================== */

export function getEvidenceGraph(
  caseId: number
) {

  return request<EvidenceGraph>(
    `/api/graph/cases/${caseId}`
  );
}


export function rebuildEvidenceGraph(
  caseId: number
) {

  return request<EvidenceGraph>(
    `/api/graph/cases/${caseId}/rebuild`,
    {
      method: "POST",
    }
  );
}
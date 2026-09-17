export type ForensicCase = {
  id: number;
  case_code: string;
  name: string;
  case_type: string;
  description: string;
  investigator: string;
  status: string;
  created_at: string;
  updated_at: string;
};

export type CreateCasePayload = {
  name: string;
  case_type: string;
  description: string;
  investigator: string;
};

export type LedgerEntry = {
  id: number;
  case_id: number;
  event_type: string;
  event_data: string;
  timestamp: string;
  previous_hash: string;
  current_hash: string;
};

export type Evidence = {
  id: number;
  evidence_code: string;
  case_id: number;
  original_filename: string;
  file_extension: string;
  mime_type: string;
  file_size: number;
  sha256: string;
  sha1: string;
  md5: string;
  entropy: number;
  integrity_status: string;
  verified_at: string | null;
  status: string;
  uploaded_at: string;
};

export type MLPrediction = {
  id: number;
  case_id: number;
  evidence_id: number;
  model_name: string;
  predicted_label: number;
  predicted_class: string;
  benign_probability: number;
  malicious_probability: number;
  risk_level: string;
  created_at: string;
};

export type MLExplanationFeature = {
  feature: string;
  label: string;
  value: number;
  display_value: string;
  importance: number;
  importance_percent: number;
  interpretation: string;
};

export type MLExplanation = {
  model_name: string;
  predicted_class: string;
  benign_probability: number;
  malicious_probability: number;
  summary: string;
  top_features: MLExplanationFeature[];
  explanation_type: string;
  disclaimer: string;
};

export type TriageFinding = {
  severity:
    | "INFO"
    | "LOW"
    | "MEDIUM"
    | "HIGH";

  title: string;
  detail: string;
};

export type TriageIndicator = {
  type: string;
  value: string;
};


/* ======================================================
   ARTIFACT-AWARE STRUCTURED EVIDENCE
====================================================== */

export type StructuredEvidencePrimitive =
  | string
  | number
  | boolean
  | null;


export type StructuredEvidenceValue =
  | StructuredEvidencePrimitive
  | StructuredEvidencePrimitive[]
  | {
      [key: string]:
        StructuredEvidenceValue;
    };


export type StructuredEvidenceKeyValueItem = {
  label: string;
  value: StructuredEvidenceValue;
};


export type StructuredEvidenceColumn = {
  key: string;
  label: string;
};


export type StructuredEvidenceRecord = {
  [key: string]:
    StructuredEvidenceValue;
};


export type StructuredEvidenceGroup = {
  key: string;
  label: string;
  values: StructuredEvidenceValue[];
};


export type StructuredEvidenceKeyValueSection = {
  key: string;
  label: string;
  kind: "key_value";
  items: StructuredEvidenceKeyValueItem[];
};


export type StructuredEvidenceRecordsSection = {
  key: string;
  label: string;
  kind: "records";
  columns: StructuredEvidenceColumn[];
  records: StructuredEvidenceRecord[];
};


export type StructuredEvidenceGroupsSection = {
  key: string;
  label: string;
  kind: "groups";
  groups: StructuredEvidenceGroup[];
};


export type StructuredEvidenceSection =
  | StructuredEvidenceKeyValueSection
  | StructuredEvidenceRecordsSection
  | StructuredEvidenceGroupsSection;


export type StructuredEvidence = {
  schema_version: number;

  artifact_type: string;
  domain: string;

  display_name: string;

  sections: StructuredEvidenceSection[];
};


export type ArtifactTriageResult = {
  id: number;

  case_id: number;
  evidence_id: number;

  evidence_code: string;
  filename: string;
  extension: string;

  analyzer: string;
  analysis_method: string;

  domain?: string | null;
  artifact_type?: string | null;
  confidence?: number | null;
  extractor?: string | null;

  structured_evidence?:
    StructuredEvidence | null;

  risk_score: number;
  risk_level: string;

  entropy?: number | null;

  predicted_class?: string | null;
  model_name?: string | null;

  benign_probability?: number | null;
  malicious_probability?: number | null;

  image_dimensions?: {
    width: number;
    height: number;
  } | null;

  findings: TriageFinding[];
  indicators: TriageIndicator[];

  limitations: string;
  created_at: string;
};


/* ======================================================
   ATTENTION
====================================================== */

export type EvidenceAttention = {
  id: number;

  case_id: number;
  evidence_id: number;

  view_count: number;
  revisit_count: number;

  total_view_seconds: number;
  focused_seconds: number;
  longest_view_seconds: number;

  first_viewed_at: string | null;
  last_viewed_at: string | null;

  updated_at: string;
};

export type AttentionUpdate = {
  dwell_seconds: number;
  focused_seconds: number;
  new_view: boolean;
};

export type AttentionCaseSummary = {
  case_id: number;

  total_evidence: number;

  reviewed_evidence: number;
  unreviewed_evidence: number;

  total_view_seconds: number;
  average_view_seconds: number;

  total_views: number;
  total_revisits: number;

  coverage_percent: number;
};


/* ======================================================
   ADVANCED COVERAGE
====================================================== */

export type CoverageComponents = {
  focused_duration: number;
  views: number;
  revisits: number;
  visible_tab_ratio: number;
  investigation_actions: number;
};

export type CoverageAttention = {
  view_count: number;
  revisit_count: number;
  total_view_seconds: number;
  focused_seconds: number;
};

export type CoverageActions = {
  triage_completed: boolean;
  integrity_verified: boolean;
  completed: number;
  applicable: number;
};

export type EvidenceCoverageItem = {
  evidence_id: number;
  evidence_code: string;

  filename: string;
  extension: string;

  coverage_score: number;

  coverage_level:
    | "UNREVIEWED"
    | "MINIMAL"
    | "PARTIAL"
    | "STRONG"
    | "THOROUGH";

  components: CoverageComponents;

  attention: CoverageAttention;

  actions: CoverageActions;

  forensic_risk: number | null;
  risk_level: string | null;

  reasons: string[];
};

export type CoverageSummary = {
  total_evidence: number;

  reviewed_evidence: number;
  unreviewed_evidence: number;

  strong_or_better: number;
  thoroughly_covered: number;

  average_coverage: number;

  lowest_coverage: number;
  highest_coverage: number;
};

export type CoverageThresholds = {
  full_focused_seconds: number;
  full_view_count: number;
  full_revisit_count: number;
};

export type CoverageReport = {
  case_id: number;

  formula: string;

  thresholds: CoverageThresholds;

  summary: CoverageSummary;

  evidence_coverage: EvidenceCoverageItem[];

  disclaimer: string;
};


/* ======================================================
   BLIND SPOTS
====================================================== */

export type BlindSpotReviewComponents = {
  focused_duration: number;
  views: number;
  revisits: number;
  visible_tab_ratio: number;
  investigation_actions: number;
};

export type BlindSpotActions = {
  triage_completed: boolean;
  integrity_verified: boolean;
  completed: number;
  applicable: number;
};

export type BlindSpotItem = {
  evidence_id: number;
  evidence_code: string;

  filename: string;
  extension: string;

  forensic_risk: number;
  risk_level: string;

  review_score: number;

  coverage_score: number;
  coverage_level: string;

  blind_spot_score: number;

  severity:
    | "HIGH"
    | "MEDIUM"
    | "LOW";

  view_count: number;
  revisit_count: number;

  dwell_seconds: number;
  focused_seconds: number;

  focus_ratio: number;

  review_components:
    BlindSpotReviewComponents;

  actions:
    BlindSpotActions;

  reasons: string[];
};

export type BlindSpotSummary = {
  analyzed_evidence: number;

  high_blind_spots: number;
  medium_blind_spots: number;
  low_blind_spots: number;

  reviewed_evidence: number;
  unreviewed_evidence: number;
};

export type BlindSpotReport = {
  case_id: number;

  formula: string;

  coverage_formula: string;

  summary: BlindSpotSummary;

  blind_spots: BlindSpotItem[];

  disclaimer: string;
};


/* ======================================================
   AI FORENSIC ANALYST
====================================================== */

export type AnalystPriorityItem = {
  evidence_id: number;
  evidence_code: string;
  filename: string;

  priority_score: number;

  forensic_risk: number | null;
  coverage_score: number | null;
  blind_spot_score: number | null;

  reasons: string[];
};

export type AnalystRecommendedNextAction = {
  evidence_id: number;
  filename: string;
  recommendation: string;
  reason: string;
};

export type AnalystBriefCoverage = {
  average: number;
  strong_or_better: number;
  thorough: number;
};

export type AnalystCaseBrief = {
  case_id: number;
  case_code: string;
  case_name: string;
  status: string;

  headline: string;

  coverage:
    AnalystBriefCoverage;

  observations: string[];

  recommended_next_actions:
    AnalystRecommendedNextAction[];

  top_priority:
    AnalystPriorityItem[];

  disclaimer: string;
};

export type AnalystCaseInfo = {
  id: number;
  case_code: string;
  name: string;
  case_type: string;
  description: string;
  investigator: string;
  status: string;
};

export type AnalystBriefResponse = {
  case: AnalystCaseInfo;

  brief: AnalystCaseBrief;

  priority_queue:
    AnalystPriorityItem[];
};

export type AnalystAnswerResponse = {
  case_id: number;

  question: string;

  answer: string;

  evidence_references: string[];

  recommended_actions: string[];

  limitations: string[];

  model_name: string;

  grounded: boolean;
};


/* ======================================================
   ADVANCED EVIDENCE GRAPH
====================================================== */

export type GraphRelationType =
  | "CONTAINS"
  | "SAME_SHA256"
  | "SHARED_HASH"
  | "SHARED_IP"
  | "SHARED_DOMAIN"
  | "SHARED_URL"
  | "SHARED_EMAIL"
  | "SHARED_INDICATOR"
  | "SAME_FILENAME_DIFFERENT_HASH";


export type GraphNode = {
  id: string;

  type:
    | "case"
    | "evidence";

  label: string;
  subtitle: string;

  status?: string | null;

  evidence_id?: number | null;

  extension?: string | null;

  size?: number | null;

  entropy?: number | null;

  integrity?: string | null;

  risk?: number | null;

  risk_level?: string | null;

  risk_source?: string | null;

  analyzer?: string | null;
};


export type GraphEdge = {
  id: string;

  source: string;
  target: string;

  type: GraphRelationType;

  label: string;

  strength: number;

  level:
    | "STRUCTURAL"
    | "STRONG"
    | "MEDIUM"
    | "WEAK";

  indicator_type?: string | null;

  indicator_value?: string | null;

  reason?: string | null;
};


export type EvidenceGraphSummary = {
  total_nodes: number;
  total_edges: number;

  evidence_nodes: number;

  analyzed_nodes: number;

  high_risk_nodes: number;
  suspicious_nodes: number;

  correlated_evidence: number;
  uncorrelated_evidence: number;

  correlation_links: number;

  strong_correlations: number;
  medium_correlations: number;
  weak_correlations: number;

  clusters: number;

  relationship_types:
    Record<string, number>;

  /* Legacy fields retained by backend */
  duplicate_links: number;
  same_type_links: number;
  entropy_links: number;
  risk_similarity_links: number;
};


export type GraphClusterMember = {
  evidence_id: number;
  evidence_code: string;
  filename: string;
};


export type GraphCluster = {
  cluster_id: string;

  member_count: number;
  relationship_count: number;

  maximum_strength: number;
  average_strength: number;

  relation_types: string[];

  members: GraphClusterMember[];
};


export type GraphMethodology = {
  strong_threshold: number;
  medium_threshold: number;
  rules: string[];
};


export type EvidenceGraph = {
  success: boolean;

  case_id: number;

  case_code: string;

  nodes: GraphNode[];

  edges: GraphEdge[];

  clusters: GraphCluster[];

  summary: EvidenceGraphSummary;

  methodology: GraphMethodology;

  disclaimer: string;
};
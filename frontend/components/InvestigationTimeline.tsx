"use client";

import {
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";


/* ======================================================
   TYPES
====================================================== */


type TimelineEvidenceReference = {
  evidence_id: number;
  evidence_code: string;
  filename: string;
};


type TimelineEvent = {
  timeline_id: string;

  source:
    | "CHAIN_OF_CUSTODY"
    | "INVESTIGATOR_ATTENTION"
    | "EVIDENCE_RECORD"
    | string;

  source_id: number;

  event_type: string;

  category:
    | "EVIDENCE"
    | "INTEGRITY"
    | "ANALYSIS"
    | "REVIEW"
    | "CORRELATION"
    | "COVERAGE"
    | "AI"
    | "AUDIT";

  title: string;

  description: string;

  timestamp: string;

  severity:
    | "INFO"
    | "MEDIUM"
    | "HIGH";

  related_evidence:
    TimelineEvidenceReference[];

  metadata:
    Record<
      string,
      unknown
    >;
};


type TimelineSummary = {
  total_events: number;

  evidence_touched: number;

  category_counts:
    Record<
      string,
      number
    >;

  severity_counts:
    Record<
      string,
      number
    >;

  first_event_at:
    string | null;

  latest_event_at:
    string | null;
};


type TimelineResponse = {
  case_id: number;
  case_code: string;
  case_name: string;

  summary:
    TimelineSummary;

  events:
    TimelineEvent[];

  categories:
    string[];

  methodology:
    string[];

  disclaimer:
    string;
};


type ReplayState = {
  registered_evidence: number;

  analyzed_evidence: number;

  reviewed_evidence: number;

  integrity_verified: number;

  active_integrity_failures: number;

  analysis_runs: number;

  integrity_checks: number;

  integrity_failures_total: number;

  correlation_runs: number;

  correlation_relationships: number;

  strong_correlations: number;

  medium_correlations: number;

  correlation_clusters: number;

  coverage_events: number;

  blind_spot_runs: number;

  ai_queries: number;

  audit_events: number;

  replay_stage:
    | "EMPTY"
    | "INGESTION"
    | "TRIAGE"
    | "INVESTIGATION"
    | "CORRELATION"
    | "AI_ASSISTED"
    | string;
};


type ReplayDelta = {
  registered: number[];

  analyzed: number[];

  reviewed: number[];

  integrity_verified: number[];

  integrity_failed: number[];

  correlation_updated: boolean;

  coverage_updated: boolean;

  ai_used: boolean;
};


type ReplaySnapshot = {
  step: number;

  total_steps: number;

  progress_percent: number;

  timestamp: string;

  event:
    TimelineEvent;

  state_before:
    ReplayState;

  state:
    ReplayState;

  delta:
    ReplayDelta;

  milestone:
    string | null;
};


type ReplayMilestone = {
  step: number;

  timestamp: string;

  milestone: string;

  title: string;

  event_type: string;
};


type ReplayResponse = {
  case_id: number;
  case_code: string;
  case_name: string;

  total_steps: number;

  initial_state:
    ReplayState;

  final_state:
    ReplayState;

  milestones:
    ReplayMilestone[];

  snapshots:
    ReplaySnapshot[];

  methodology:
    string[];

  disclaimer:
    string;
};


type Props = {
  caseId: number;

  onOpenEvidence:
    (
      evidenceId: number
    ) => void;
};


/* ======================================================
   API
====================================================== */


const API_URL =
  process.env
    .NEXT_PUBLIC_API_URL
  ??
  "http://127.0.0.1:8000";


async function request<T>(
  path: string
): Promise<T> {

  const response =
    await fetch(
      `${API_URL}${path}`,
      {
        cache:
          "no-store",
      }
    );


  if (!response.ok) {

    let message =
      `Request failed with status ${response.status}.`;


    try {

      const data =
        await response.json();


      if (
        data
        &&
        data.detail
      ) {

        message =
          typeof data.detail
          === "string"
            ? data.detail
            : JSON.stringify(
                data.detail
              );
      }

    } catch {
      // Keep fallback message.
    }


    throw new Error(
      message
    );
  }


  return response.json();
}


/* ======================================================
   FORMATTERS
====================================================== */


function formatTimestamp(
  value: string
) {

  const date =
    new Date(
      value
    );


  if (
    Number.isNaN(
      date.getTime()
    )
  ) {

    return value;
  }


  return date.toLocaleString(
    undefined,
    {
      dateStyle:
        "medium",

      timeStyle:
        "medium",
    }
  );
}


function formatClockTime(
  value: string
) {

  const date =
    new Date(
      value
    );


  if (
    Number.isNaN(
      date.getTime()
    )
  ) {

    return value;
  }


  return date.toLocaleTimeString(
    undefined,
    {
      hour:
        "2-digit",

      minute:
        "2-digit",

      second:
        "2-digit",
    }
  );
}


function readableName(
  value: string
) {

  return value
    .replace(
      /_/g,
      " "
    );
}


/* ======================================================
   COLORS
====================================================== */


function categoryColor(
  category: string
) {

  switch (category) {

    case "EVIDENCE":
      return "#7fc6ff";

    case "INTEGRITY":
      return "#70e5b5";

    case "ANALYSIS":
      return "#e993ff";

    case "REVIEW":
      return "#8ad4ff";

    case "CORRELATION":
      return "#a58cff";

    case "COVERAGE":
      return "#f2cb70";

    case "AI":
      return "#68e8d1";

    default:
      return "#9aa9ba";
  }
}


function severityColor(
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


  return "#7fc6ff";
}


function stageColor(
  stage: string
) {

  switch (stage) {

    case "EMPTY":
      return "#9aa9ba";

    case "INGESTION":
      return "#7fc6ff";

    case "TRIAGE":
      return "#e993ff";

    case "INVESTIGATION":
      return "#70e5b5";

    case "CORRELATION":
      return "#a58cff";

    case "AI_ASSISTED":
      return "#68e8d1";

    default:
      return "#9aa9ba";
  }
}


/* ======================================================
   STATE CARD
====================================================== */


function StateMetric(
  props: {
    label: string;
    value:
      string | number;

    accent?: string;
  }
) {

  return (

    <div
      style={{
        padding:
          "12px",

        border:
          "1px solid var(--border)",

        borderRadius:
          "12px",

        background:
          "rgba(255,255,255,0.025)",
      }}
    >

      <span
        style={{
          display:
            "block",

          fontSize:
            "9px",

          fontWeight:
            700,

          letterSpacing:
            "0.08em",

          opacity:
            0.55,
        }}
      >
        {
          props.label
        }
      </span>


      <strong
        style={{
          display:
            "block",

          marginTop:
            "5px",

          fontSize:
            "20px",

          color:
            props.accent
            ??
            "inherit",
        }}
      >
        {
          props.value
        }
      </strong>

    </div>

  );
}


/* ======================================================
   COMPONENT
====================================================== */


export default function InvestigationTimeline(
  {
    caseId,
    onOpenEvidence,
  }: Props
) {

  const [
    timeline,
    setTimeline,
  ] =
    useState<TimelineResponse | null>(
      null
    );


  const [
    replay,
    setReplay,
  ] =
    useState<ReplayResponse | null>(
      null
    );


  const [
    selectedStep,
    setSelectedStep,
  ] =
    useState(1);


  const [
    selectedCategory,
    setSelectedCategory,
  ] =
    useState<
      string | null
    >(
      null
    );


  const [
    replayMode,
    setReplayMode,
  ] =
    useState(false);


  const [
    playing,
    setPlaying,
  ] =
    useState(false);


  const [
    loading,
    setLoading,
  ] =
    useState(true);


  const [
    error,
    setError,
  ] =
    useState("");


  const intervalRef =
    useRef<
      ReturnType<
        typeof setInterval
      >
      |
      null
    >(
      null
    );


  /* ====================================================
     LOAD
  ==================================================== */


  async function loadData() {

    setLoading(
      true
    );


    setError(
      ""
    );


    try {

      const [
        timelineData,
        replayData,
      ] =
        await Promise.all([

          request<TimelineResponse>(
            `/api/timeline/cases/${caseId}`
          ),

          request<ReplayResponse>(
            `/api/timeline/cases/${caseId}/replay`
          ),

        ]);


      setTimeline(
        timelineData
      );


      setReplay(
        replayData
      );


      if (
        replayData.total_steps
        > 0
      ) {

        setSelectedStep(
          replayData.total_steps
        );

      } else {

        setSelectedStep(
          1
        );
      }


    } catch (error) {

      setError(
        error instanceof Error
          ? error.message
          : "Unable to load investigation timeline."
      );

    } finally {

      setLoading(
        false
      );
    }
  }


  useEffect(() => {

    void loadData();

  }, [
    caseId
  ]);


  /* ====================================================
     PLAYBACK
  ==================================================== */


  useEffect(() => {

    if (
      !playing
      ||
      !replay
      ||
      replay.total_steps === 0
    ) {

      return;
    }


    intervalRef.current =
      setInterval(
        () => {

          setSelectedStep(
            (current) => {

              if (
                current
                >=
                replay.total_steps
              ) {

                setPlaying(
                  false
                );


                return current;
              }


              return (
                current + 1
              );
            }
          );

        },
        1250
      );


    return () => {

      if (
        intervalRef.current
      ) {

        clearInterval(
          intervalRef.current
        );


        intervalRef.current =
          null;
      }
    };

  }, [
    playing,
    replay
  ]);


  useEffect(() => {

    return () => {

      if (
        intervalRef.current
      ) {

        clearInterval(
          intervalRef.current
        );
      }
    };

  }, []);


  /* ====================================================
     SELECTED SNAPSHOT
  ==================================================== */


  const selectedSnapshot =
    useMemo(
      () => {

        if (
          !replay
          ||
          replay.total_steps
          === 0
        ) {

          return null;
        }


        return (
          replay.snapshots[
            Math.max(
              0,
              Math.min(
                selectedStep - 1,
                replay.snapshots.length - 1
              )
            )
          ]
          ??
          null
        );

      },
      [
        replay,
        selectedStep
      ]
    );


  const filteredEvents =
    useMemo(
      () => {

        if (!timeline) {

          return [];
        }


        if (
          !selectedCategory
        ) {

          return timeline.events;
        }


        return (
          timeline.events.filter(
            (event) =>
              event.category
              === selectedCategory
          )
        );

      },
      [
        timeline,
        selectedCategory
      ]
    );


  /* ====================================================
     NAVIGATION
  ==================================================== */


  function previousStep() {

    setPlaying(
      false
    );


    setSelectedStep(
      (current) =>
        Math.max(
          1,
          current - 1
        )
    );
  }


  function nextStep() {

    if (!replay) {
      return;
    }


    setPlaying(
      false
    );


    setSelectedStep(
      (current) =>
        Math.min(
          replay.total_steps,
          current + 1
        )
    );
  }


  function restartReplay() {

    setPlaying(
      false
    );


    setReplayMode(
      true
    );


    setSelectedStep(
      1
    );
  }


  function jumpToStep(
    step: number
  ) {

    setPlaying(
      false
    );


    setReplayMode(
      true
    );


    setSelectedStep(
      step
    );
  }


  /* ====================================================
     LOADING / ERROR
  ==================================================== */


  if (loading) {

    return (

      <div
        className="centerScreen"
        style={{
          minHeight:
            "420px",
        }}
      >
        Building investigation history...
      </div>

    );
  }


  if (error) {

    return (

      <div className="formError">

        {
          error
        }


        <button
          type="button"
          onClick={() =>
            void loadData()
          }
          style={{
            marginLeft:
              "12px",
          }}
        >
          Retry
        </button>

      </div>

    );
  }


  if (
    !timeline
    ||
    !replay
  ) {

    return (

      <div className="emptyState">
        Timeline unavailable.
      </div>

    );
  }


  /* ====================================================
     UI
  ==================================================== */


  return (

    <section>

      {/* =================================================
          HEADER STATS
      ================================================= */}


      <section className="phaseStats">

        <article>

          <span>
            EVENTS
          </span>

          <strong>
            {
              timeline.summary
                .total_events
            }
          </strong>

        </article>


        <article>

          <span>
            EVIDENCE TOUCHED
          </span>

          <strong>
            {
              timeline.summary
                .evidence_touched
            }
          </strong>

        </article>


        <article>

          <span>
            MILESTONES
          </span>

          <strong>
            {
              replay.milestones.length
            }
          </strong>

        </article>


        <article>

          <span>
            REPLAY STAGE
          </span>

          <strong
            style={{
              color:
                stageColor(
                  selectedSnapshot
                    ?.state
                    .replay_stage
                  ??
                  replay
                    .final_state
                    .replay_stage
                ),

              fontSize:
                "14px",
            }}
          >
            {
              readableName(
                selectedSnapshot
                  ?.state
                  .replay_stage
                ??
                replay
                  .final_state
                  .replay_stage
              )
            }
          </strong>

        </article>

      </section>


      {/* =================================================
          MODE HEADER
      ================================================= */}


      <div
        style={{
          display:
            "flex",

          justifyContent:
            "space-between",

          alignItems:
            "center",

          gap:
            "14px",

          marginTop:
            "18px",

          marginBottom:
            "14px",
        }}
      >

        <div>

          <span className="eyebrow">
            INVESTIGATION HISTORY
          </span>


          <h2
            style={{
              marginTop:
                "4px",
            }}
          >
            {
              replayMode
                ? "Investigation Replay"
                : "Forensic Timeline"
            }
          </h2>

        </div>


        <div
          style={{
            display:
              "flex",

            gap:
              "8px",
          }}
        >

          <button
            type="button"
            onClick={() => {

              setPlaying(
                false
              );

              setReplayMode(
                false
              );
            }}
          >
            Timeline
          </button>


          <button
            type="button"
            onClick={() =>
              setReplayMode(
                true
              )
            }
          >
            Replay
          </button>


          <button
            type="button"
            onClick={() =>
              void loadData()
            }
          >
            Refresh
          </button>

        </div>

      </div>


      {/* =================================================
          TIMELINE MODE
      ================================================= */}


      {
        !replayMode
        &&
        (

          <section
            style={{
              display:
                "grid",

              gridTemplateColumns:
                "minmax(0,1fr) 330px",

              gap:
                "18px",
            }}
          >

            <div
              style={{
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

              {/* CATEGORY FILTERS */}


              <div
                style={{
                  display:
                    "flex",

                  flexWrap:
                    "wrap",

                  gap:
                    "7px",

                  marginBottom:
                    "18px",
                }}
              >

                <button
                  type="button"
                  onClick={() =>
                    setSelectedCategory(
                      null
                    )
                  }
                  style={{
                    opacity:
                      selectedCategory
                      === null
                        ? 1
                        : 0.55,
                  }}
                >
                  All
                </button>


                {
                  timeline.categories.map(
                    (category) => (

                      <button
                        type="button"
                        key={
                          category
                        }
                        onClick={() =>
                          setSelectedCategory(
                            category
                          )
                        }
                        style={{
                          color:
                            categoryColor(
                              category
                            ),

                          opacity:
                            selectedCategory
                            === category
                              ? 1
                              : 0.6,
                        }}
                      >
                        {
                          category
                        }
                      </button>

                    )
                  )
                }

              </div>


              {
                filteredEvents.length
                === 0
                ? (

                  <div className="emptyState">
                    No timeline events in this category.
                  </div>

                )
                : (

                  <div
                    style={{
                      position:
                        "relative",

                      paddingLeft:
                        "24px",
                    }}
                  >

                    <div
                      style={{
                        position:
                          "absolute",

                        left:
                          "7px",

                        top:
                          "8px",

                        bottom:
                          "8px",

                        width:
                          "1px",

                        background:
                          "var(--border)",
                      }}
                    />


                    {
                      filteredEvents.map(
                        (
                          event
                        ) => {

                          const originalIndex =
                            timeline.events.findIndex(
                              (item) =>
                                item.timeline_id
                                === event.timeline_id
                            );


                          const replayStep =
                            originalIndex + 1;


                          return (

                            <article
                              key={
                                event.timeline_id
                              }
                              style={{
                                position:
                                  "relative",

                                padding:
                                  "0 0 22px 14px",
                              }}
                            >

                              <div
                                style={{
                                  position:
                                    "absolute",

                                  left:
                                    "-21px",

                                  top:
                                    "5px",

                                  width:
                                    "10px",

                                  height:
                                    "10px",

                                  borderRadius:
                                    "50%",

                                  background:
                                    severityColor(
                                      event.severity
                                    ),

                                  boxShadow:
                                    `0 0 0 4px ${categoryColor(
                                      event.category
                                    )}22`,
                                }}
                              />


                              <div
                                style={{
                                  display:
                                    "flex",

                                  justifyContent:
                                    "space-between",

                                  gap:
                                    "14px",
                                }}
                              >

                                <div>

                                  <div
                                    style={{
                                      display:
                                        "flex",

                                      gap:
                                        "8px",

                                      alignItems:
                                        "center",

                                      flexWrap:
                                        "wrap",
                                    }}
                                  >

                                    <span
                                      style={{
                                        color:
                                          categoryColor(
                                            event.category
                                          ),

                                        fontSize:
                                          "9px",

                                        fontWeight:
                                          800,
                                      }}
                                    >
                                      {
                                        event.category
                                      }
                                    </span>


                                    {
                                      event.severity
                                      !== "INFO"
                                      &&
                                      (

                                        <span
                                          style={{
                                            color:
                                              severityColor(
                                                event.severity
                                              ),

                                            fontSize:
                                              "9px",

                                            fontWeight:
                                              800,
                                          }}
                                        >
                                          {
                                            event.severity
                                          }
                                        </span>

                                      )
                                    }

                                  </div>


                                  <strong
                                    style={{
                                      display:
                                        "block",

                                      marginTop:
                                        "6px",

                                      fontSize:
                                        "14px",
                                    }}
                                  >
                                    {
                                      event.title
                                    }
                                  </strong>


                                  <p
                                    style={{
                                      marginTop:
                                        "6px",

                                      fontSize:
                                        "12px",

                                      lineHeight:
                                        "1.6",

                                      opacity:
                                        0.72,
                                    }}
                                  >
                                    {
                                      event.description
                                    }
                                  </p>

                                </div>


                                <div
                                  style={{
                                    textAlign:
                                      "right",

                                    flexShrink:
                                      0,
                                  }}
                                >

                                  <span
                                    style={{
                                      display:
                                        "block",

                                      fontSize:
                                        "10px",

                                      opacity:
                                        0.58,
                                    }}
                                  >
                                    {
                                      formatClockTime(
                                        event.timestamp
                                      )
                                    }
                                  </span>


                                  <button
                                    type="button"
                                    onClick={() =>
                                      jumpToStep(
                                        replayStep
                                      )
                                    }
                                    style={{
                                      marginTop:
                                        "7px",

                                      fontSize:
                                        "9px",
                                    }}
                                  >
                                    Replay step
                                  </button>

                                </div>

                              </div>


                              {
                                event
                                  .related_evidence
                                  .length > 0
                                &&
                                (

                                  <div
                                    style={{
                                      display:
                                        "flex",

                                      flexWrap:
                                        "wrap",

                                      gap:
                                        "6px",

                                      marginTop:
                                        "9px",
                                    }}
                                  >

                                    {
                                      event
                                        .related_evidence
                                        .map(
                                          (
                                            item
                                          ) => (

                                            <button
                                              type="button"
                                              key={
                                                `${event.timeline_id}-${item.evidence_id}`
                                              }
                                              onClick={() =>
                                                onOpenEvidence(
                                                  item.evidence_id
                                                )
                                              }
                                              style={{
                                                padding:
                                                  "6px 8px",

                                                border:
                                                  "1px solid var(--border)",

                                                borderRadius:
                                                  "999px",

                                                background:
                                                  "rgba(255,255,255,0.025)",

                                                fontSize:
                                                  "9px",
                                              }}
                                            >
                                              {
                                                item.evidence_code
                                              }
                                            </button>

                                          )
                                        )
                                    }

                                  </div>

                                )
                              }

                            </article>

                          );
                        }
                      )
                    }

                  </div>

                )
              }

            </div>


            {/* TIMELINE SIDE PANEL */}


            <aside className="inspectorPanel">

              <span className="eyebrow">
                INVESTIGATION WINDOW
              </span>


              <h3
                style={{
                  marginTop:
                    "7px",
                }}
              >
                {
                  timeline.case_name
                }
              </h3>


              <div
                className="inspectorHint"
                style={{
                  marginTop:
                    "16px",
                }}
              >

                <span className="eyebrow">
                  FIRST RECORDED EVENT
                </span>


                <strong
                  style={{
                    display:
                      "block",

                    marginTop:
                      "6px",
                  }}
                >
                  {
                    timeline.summary
                      .first_event_at
                      ? formatTimestamp(
                          timeline.summary
                            .first_event_at
                        )
                      : "—"
                  }
                </strong>

              </div>


              <div
                className="inspectorHint"
                style={{
                  marginTop:
                    "10px",
                }}
              >

                <span className="eyebrow">
                  LATEST EVENT
                </span>


                <strong
                  style={{
                    display:
                      "block",

                    marginTop:
                      "6px",
                  }}
                >
                  {
                    timeline.summary
                      .latest_event_at
                      ? formatTimestamp(
                          timeline.summary
                            .latest_event_at
                        )
                      : "—"
                  }
                </strong>

              </div>


              <div
                style={{
                  marginTop:
                    "18px",
                }}
              >

                <span className="eyebrow">
                  EVENT DISTRIBUTION
                </span>


                {
                  Object.entries(
                    timeline.summary
                      .category_counts
                  )
                  .map(
                    (
                      [
                        category,
                        count,
                      ]
                    ) => (

                      <div
                        key={
                          category
                        }
                        style={{
                          display:
                            "flex",

                          justifyContent:
                            "space-between",

                          gap:
                            "12px",

                          marginTop:
                            "8px",

                          fontSize:
                            "11px",
                        }}
                      >

                        <span
                          style={{
                            color:
                              categoryColor(
                                category
                              ),
                          }}
                        >
                          {
                            category
                          }
                        </span>


                        <strong>
                          {
                            count
                          }
                        </strong>

                      </div>

                    )
                  )
                }

              </div>


              {
                replay.milestones.length > 0
                &&
                (

                  <div
                    style={{
                      marginTop:
                        "20px",
                    }}
                  >

                    <span className="eyebrow">
                      MILESTONES
                    </span>


                    {
                      replay.milestones.map(
                        (
                          milestone
                        ) => (

                          <button
                            type="button"
                            key={
                              `${milestone.step}-${milestone.milestone}`
                            }
                            onClick={() =>
                              jumpToStep(
                                milestone.step
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
                                "10px",

                              border:
                                "1px solid var(--border)",

                              borderRadius:
                                "10px",

                              background:
                                "rgba(255,255,255,0.025)",
                            }}
                          >

                            <span
                              style={{
                                display:
                                  "block",

                                fontSize:
                                  "9px",

                                color:
                                  "#9dd4ff",

                                fontWeight:
                                  700,
                              }}
                            >
                              STEP{" "}
                              {
                                milestone.step
                              }
                            </span>


                            <strong
                              style={{
                                display:
                                  "block",

                                marginTop:
                                  "4px",

                                fontSize:
                                  "11px",
                              }}
                            >
                              {
                                readableName(
                                  milestone.milestone
                                )
                              }
                            </strong>

                          </button>

                        )
                      )
                    }

                  </div>

                )
              }


              <div
                className="inspectorHint"
                style={{
                  marginTop:
                    "20px",
                }}
              >

                <span className="eyebrow">
                  LIMITATION
                </span>


                <p
                  style={{
                    marginTop:
                      "7px",

                    lineHeight:
                      "1.6",
                  }}
                >
                  {
                    timeline.disclaimer
                  }
                </p>

              </div>

            </aside>

          </section>

        )
      }


      {/* =================================================
          REPLAY MODE
      ================================================= */}


      {
        replayMode
        &&
        selectedSnapshot
        &&
        (

          <section>

            {/* PLAYBACK CONTROLS */}


            <div
              style={{
                border:
                  "1px solid var(--border)",

                borderRadius:
                  "16px",

                background:
                  "var(--panel)",

                padding:
                  "14px 16px",
              }}
            >

              <div
                style={{
                  display:
                    "flex",

                  alignItems:
                    "center",

                  justifyContent:
                    "space-between",

                  gap:
                    "12px",

                  flexWrap:
                    "wrap",
                }}
              >

                <div
                  style={{
                    display:
                      "flex",

                    gap:
                      "7px",
                  }}
                >

                  <button
                    type="button"
                    onClick={
                      restartReplay
                    }
                  >
                    ⏮
                  </button>


                  <button
                    type="button"
                    onClick={
                      previousStep
                    }
                    disabled={
                      selectedStep <= 1
                    }
                  >
                    ◀ Previous
                  </button>


                  <button
                    type="button"
                    onClick={() =>
                      setPlaying(
                        (
                          current
                        ) =>
                          !current
                      )
                    }
                  >
                    {
                      playing
                        ? "⏸ Pause"
                        : "▶ Play"
                    }
                  </button>


                  <button
                    type="button"
                    onClick={
                      nextStep
                    }
                    disabled={
                      selectedStep
                      >=
                      replay.total_steps
                    }
                  >
                    Next ▶
                  </button>

                </div>


                <div
                  style={{
                    textAlign:
                      "right",
                  }}
                >

                  <strong>
                    STEP{" "}
                    {
                      selectedStep
                    }
                    {" / "}
                    {
                      replay.total_steps
                    }
                  </strong>


                  <span
                    style={{
                      display:
                        "block",

                      marginTop:
                        "2px",

                      fontSize:
                        "10px",

                      opacity:
                        0.55,
                    }}
                  >
                    {
                      selectedSnapshot
                        .progress_percent
                    }%
                  </span>

                </div>

              </div>


              <input
                type="range"
                min={1}
                max={
                  Math.max(
                    replay.total_steps,
                    1
                  )
                }
                value={
                  selectedStep
                }
                onChange={
                  (
                    event
                  ) => {

                    setPlaying(
                      false
                    );


                    setSelectedStep(
                      Number(
                        event.target.value
                      )
                    );
                  }
                }
                style={{
                  width:
                    "100%",

                  marginTop:
                    "14px",
                }}
              />

            </div>


            <section
              style={{
                display:
                  "grid",

                gridTemplateColumns:
                  "minmax(0,1fr) 360px",

                gap:
                  "18px",

                marginTop:
                  "18px",
              }}
            >

              {/* CURRENT EVENT */}


              <div>

                <div
                  style={{
                    border:
                      `1px solid ${categoryColor(
                        selectedSnapshot
                          .event
                          .category
                      )}44`,

                    borderRadius:
                      "18px",

                    background:
                      "var(--panel)",

                    padding:
                      "22px",
                  }}
                >

                  <div
                    style={{
                      display:
                        "flex",

                      justifyContent:
                        "space-between",

                      alignItems:
                        "flex-start",

                      gap:
                        "14px",
                    }}
                  >

                    <div>

                      <span
                        style={{
                          color:
                            categoryColor(
                              selectedSnapshot
                                .event
                                .category
                            ),

                          fontSize:
                            "10px",

                          fontWeight:
                            800,

                          letterSpacing:
                            "0.08em",
                        }}
                      >
                        {
                          selectedSnapshot
                            .event
                            .category
                        }
                      </span>


                      <h2
                        style={{
                          marginTop:
                            "7px",
                        }}
                      >
                        {
                          selectedSnapshot
                            .event
                            .title
                        }
                      </h2>


                      <p
                        style={{
                          marginTop:
                            "10px",

                          lineHeight:
                            "1.7",

                          opacity:
                            0.76,
                        }}
                      >
                        {
                          selectedSnapshot
                            .event
                            .description
                        }
                      </p>

                    </div>


                    <div
                      style={{
                        textAlign:
                          "right",

                        flexShrink:
                          0,
                      }}
                    >

                      <strong
                        style={{
                          color:
                            severityColor(
                              selectedSnapshot
                                .event
                                .severity
                            ),
                        }}
                      >
                        {
                          selectedSnapshot
                            .event
                            .severity
                        }
                      </strong>


                      <span
                        style={{
                          display:
                            "block",

                          marginTop:
                            "4px",

                          fontSize:
                            "10px",

                          opacity:
                            0.55,
                        }}
                      >
                        {
                          formatTimestamp(
                            selectedSnapshot
                              .timestamp
                          )
                        }
                      </span>

                    </div>

                  </div>


                  {
                    selectedSnapshot
                      .milestone
                    &&
                    (

                      <div
                        style={{
                          marginTop:
                            "16px",

                          padding:
                            "10px 12px",

                          border:
                            "1px solid rgba(127,198,255,0.25)",

                          borderRadius:
                            "10px",

                          background:
                            "rgba(127,198,255,0.05)",
                        }}
                      >

                        <span className="eyebrow">
                          MILESTONE
                        </span>


                        <strong
                          style={{
                            display:
                              "block",

                            marginTop:
                              "4px",
                          }}
                        >
                          {
                            readableName(
                              selectedSnapshot
                                .milestone
                            )
                          }
                        </strong>

                      </div>

                    )
                  }


                  {
                    selectedSnapshot
                      .event
                      .related_evidence
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
                          RELATED EVIDENCE
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
                            selectedSnapshot
                              .event
                              .related_evidence
                              .map(
                                (
                                  evidence
                                ) => (

                                  <button
                                    type="button"
                                    key={
                                      evidence.evidence_id
                                    }
                                    onClick={() =>
                                      onOpenEvidence(
                                        evidence.evidence_id
                                      )
                                    }
                                  >
                                    {
                                      evidence.evidence_code
                                    }
                                  </button>

                                )
                              )
                          }

                        </div>

                      </div>

                    )
                  }

                </div>


                {/* BEFORE / AFTER */}


                <div
                  style={{
                    display:
                      "grid",

                    gridTemplateColumns:
                      "1fr auto 1fr",

                    gap:
                      "12px",

                    alignItems:
                      "stretch",

                    marginTop:
                      "18px",
                  }}
                >

                  <div
                    style={{
                      border:
                        "1px solid var(--border)",

                      borderRadius:
                        "16px",

                      padding:
                        "16px",

                      background:
                        "rgba(255,255,255,0.02)",
                    }}
                  >

                    <span className="eyebrow">
                      BEFORE EVENT
                    </span>


                    <div
                      style={{
                        display:
                          "grid",

                        gridTemplateColumns:
                          "repeat(2,minmax(0,1fr))",

                        gap:
                          "8px",

                        marginTop:
                          "12px",
                      }}
                    >

                      <StateMetric
                        label="REGISTERED"
                        value={
                          selectedSnapshot
                            .state_before
                            .registered_evidence
                        }
                      />


                      <StateMetric
                        label="ANALYZED"
                        value={
                          selectedSnapshot
                            .state_before
                            .analyzed_evidence
                        }
                      />


                      <StateMetric
                        label="REVIEWED"
                        value={
                          selectedSnapshot
                            .state_before
                            .reviewed_evidence
                        }
                      />


                      <StateMetric
                        label="CORRELATIONS"
                        value={
                          selectedSnapshot
                            .state_before
                            .correlation_relationships
                        }
                      />

                    </div>

                  </div>


                  <div
                    style={{
                      display:
                        "grid",

                      placeItems:
                        "center",

                      fontSize:
                        "22px",

                      opacity:
                        0.5,
                    }}
                  >
                    →
                  </div>


                  <div
                    style={{
                      border:
                        "1px solid rgba(112,229,181,0.24)",

                      borderRadius:
                        "16px",

                      padding:
                        "16px",

                      background:
                        "rgba(112,229,181,0.025)",
                    }}
                  >

                    <span className="eyebrow">
                      AFTER EVENT
                    </span>


                    <div
                      style={{
                        display:
                          "grid",

                        gridTemplateColumns:
                          "repeat(2,minmax(0,1fr))",

                        gap:
                          "8px",

                        marginTop:
                          "12px",
                      }}
                    >

                      <StateMetric
                        label="REGISTERED"
                        value={
                          selectedSnapshot
                            .state
                            .registered_evidence
                        }
                        accent="#7fc6ff"
                      />


                      <StateMetric
                        label="ANALYZED"
                        value={
                          selectedSnapshot
                            .state
                            .analyzed_evidence
                        }
                        accent="#e993ff"
                      />


                      <StateMetric
                        label="REVIEWED"
                        value={
                          selectedSnapshot
                            .state
                            .reviewed_evidence
                        }
                        accent="#70e5b5"
                      />


                      <StateMetric
                        label="CORRELATIONS"
                        value={
                          selectedSnapshot
                            .state
                            .correlation_relationships
                        }
                        accent="#a58cff"
                      />

                    </div>

                  </div>

                </div>

              </div>


              {/* LIVE STATE */}


              <aside className="inspectorPanel">

                <span className="eyebrow">
                  REPLAY STATE
                </span>


                <h3
                  style={{
                    marginTop:
                      "7px",

                    color:
                      stageColor(
                        selectedSnapshot
                          .state
                          .replay_stage
                      ),
                  }}
                >
                  {
                    readableName(
                      selectedSnapshot
                        .state
                        .replay_stage
                    )
                  }
                </h3>


                <div
                  style={{
                    display:
                      "grid",

                    gridTemplateColumns:
                      "repeat(2,minmax(0,1fr))",

                    gap:
                      "8px",

                    marginTop:
                      "16px",
                  }}
                >

                  <StateMetric
                    label="EVIDENCE"
                    value={
                      selectedSnapshot
                        .state
                        .registered_evidence
                    }
                    accent="#7fc6ff"
                  />


                  <StateMetric
                    label="ANALYZED"
                    value={
                      selectedSnapshot
                        .state
                        .analyzed_evidence
                    }
                    accent="#e993ff"
                  />


                  <StateMetric
                    label="REVIEWED"
                    value={
                      selectedSnapshot
                        .state
                        .reviewed_evidence
                    }
                    accent="#70e5b5"
                  />


                  <StateMetric
                    label="VERIFIED"
                    value={
                      selectedSnapshot
                        .state
                        .integrity_verified
                    }
                  />


                  <StateMetric
                    label="INTEGRITY FAILURES"
                    value={
                      selectedSnapshot
                        .state
                        .active_integrity_failures
                    }
                    accent={
                      selectedSnapshot
                        .state
                        .active_integrity_failures
                      > 0
                        ? "#ff7474"
                        : undefined
                    }
                  />


                  <StateMetric
                    label="AI QUERIES"
                    value={
                      selectedSnapshot
                        .state
                        .ai_queries
                    }
                    accent="#68e8d1"
                  />

                </div>


                <div
                  className="integrityCard"
                  style={{
                    marginTop:
                      "16px",
                  }}
                >

                  <div
                    style={{
                      width:
                        "100%",
                    }}
                  >

                    <span className="eyebrow">
                      CORRELATION STATE
                    </span>


                    <p
                      style={{
                        marginTop:
                          "8px",
                      }}
                    >
                      Relationships:{" "}
                      <strong>
                        {
                          selectedSnapshot
                            .state
                            .correlation_relationships
                        }
                      </strong>
                    </p>


                    <p>
                      Strong:{" "}
                      <strong>
                        {
                          selectedSnapshot
                            .state
                            .strong_correlations
                        }
                      </strong>
                    </p>


                    <p>
                      Medium:{" "}
                      <strong>
                        {
                          selectedSnapshot
                            .state
                            .medium_correlations
                        }
                      </strong>
                    </p>


                    <p>
                      Clusters:{" "}
                      <strong>
                        {
                          selectedSnapshot
                            .state
                            .correlation_clusters
                        }
                      </strong>
                    </p>

                  </div>

                </div>


                <div
                  style={{
                    marginTop:
                      "18px",
                  }}
                >

                  <span className="eyebrow">
                    EVENT DELTA
                  </span>


                  <div
                    className="inspectorHint"
                    style={{
                      marginTop:
                        "8px",
                    }}
                  >

                    <p>
                      Registered:{" "}
                      <strong>
                        {
                          selectedSnapshot
                            .delta
                            .registered
                            .length
                        }
                      </strong>
                    </p>


                    <p>
                      Analyzed:{" "}
                      <strong>
                        {
                          selectedSnapshot
                            .delta
                            .analyzed
                            .length
                        }
                      </strong>
                    </p>


                    <p>
                      Reviewed:{" "}
                      <strong>
                        {
                          selectedSnapshot
                            .delta
                            .reviewed
                            .length
                        }
                      </strong>
                    </p>


                    <p>
                      Correlation Updated:{" "}
                      <strong>
                        {
                          selectedSnapshot
                            .delta
                            .correlation_updated
                            ? "YES"
                            : "NO"
                        }
                      </strong>
                    </p>


                    <p>
                      AI Used:{" "}
                      <strong>
                        {
                          selectedSnapshot
                            .delta
                            .ai_used
                            ? "YES"
                            : "NO"
                        }
                      </strong>
                    </p>

                  </div>

                </div>


                <div
                  className="inspectorHint"
                  style={{
                    marginTop:
                      "18px",
                  }}
                >

                  <span className="eyebrow">
                    REPLAY LIMITATION
                  </span>


                  <p
                    style={{
                      marginTop:
                        "7px",

                      lineHeight:
                        "1.6",
                    }}
                  >
                    {
                      replay.disclaimer
                    }
                  </p>

                </div>

              </aside>

            </section>

          </section>

        )
      }

    </section>

  );
}
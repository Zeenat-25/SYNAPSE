"use client";

import type {
  EvidenceGraph,
  GraphCluster,
  GraphEdge,
  GraphNode,
} from "@/lib/types";


type Props = {
  graph: EvidenceGraph | null;

  evidenceReferences: string[];

  onOpenEvidence:
    (evidenceCode: string) => void;

  onOpenEdge:
    (edge: GraphEdge) => void;

  onOpenCluster:
    (cluster: GraphCluster) => void;
};


function relationshipColor(
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
      return "#9aa9ba";
  }
}


function relationName(
  type: string
) {

  return type
    .replace(
      /_/g,
      " "
    );
}


function findNode(
  graph: EvidenceGraph,
  nodeId: string
): GraphNode | null {

  return (
    graph.nodes.find(
      (node) =>
        node.id === nodeId
    )
    ??
    null
  );
}


export default function AnalystCorrelationCards(
  {
    graph,
    evidenceReferences,
    onOpenEvidence,
    onOpenEdge,
    onOpenCluster,
  }: Props
) {

  if (
    !graph
    ||
    evidenceReferences.length === 0
  ) {

    return null;
  }


  const referencedCodes =
    new Set(
      evidenceReferences
    );


  const referencedNodes =
    graph.nodes.filter(
      (node) =>
        node.type === "evidence"
        &&
        referencedCodes.has(
          node.subtitle
        )
    );


  const referencedNodeIds =
    new Set(
      referencedNodes.map(
        (node) =>
          node.id
      )
    );


  const correlationEdges =
    graph.edges
      .filter(
        (edge) => {

          if (
            edge.type
            === "CONTAINS"
          ) {

            return false;
          }


          const sourceReferenced =
            referencedNodeIds.has(
              edge.source
            );


          const targetReferenced =
            referencedNodeIds.has(
              edge.target
            );


          /*
           * If the AI referenced several artifacts,
           * display deterministic relationships that
           * actually connect those cited artifacts.
           */
          if (
            referencedNodeIds.size > 1
          ) {

            return (
              sourceReferenced
              &&
              targetReferenced
            );
          }


          /*
           * If only one artifact was referenced,
           * show its real deterministic neighbors.
           */
          return (
            sourceReferenced
            ||
            targetReferenced
          );
        }
      )
      .sort(
        (
          first,
          second
        ) =>
          second.strength
          -
          first.strength
      )
      .slice(
        0,
        6
      );


  const relatedClusters =
    graph.clusters
      .filter(
        (cluster) =>
          cluster.members.some(
            (member) =>
              referencedCodes.has(
                member.evidence_code
              )
          )
      )
      .slice(
        0,
        3
      );


  if (
    correlationEdges.length === 0
    &&
    relatedClusters.length === 0
  ) {

    return null;
  }


  return (

    <div
      style={{
        marginTop: "18px",
      }}
    >

      <span className="eyebrow">
        DETERMINISTIC CORRELATIONS
      </span>


      {
        correlationEdges.length > 0
        &&
        (

          <div
            style={{
              display: "grid",
              gap: "9px",
              marginTop: "9px",
            }}
          >

            {
              correlationEdges.map(
                (edge) => {

                  const source =
                    findNode(
                      graph,
                      edge.source
                    );


                  const target =
                    findNode(
                      graph,
                      edge.target
                    );


                  return (

                    <div
                      key={
                        edge.id
                      }
                      style={{
                        border:
                          `1px solid ${relationshipColor(
                            edge.type
                          )}44`,

                        borderRadius:
                          "13px",

                        padding:
                          "12px",

                        background:
                          "rgba(255,255,255,0.025)",
                      }}
                    >

                      <div
                        style={{
                          display: "flex",
                          justifyContent:
                            "space-between",
                          gap: "12px",
                          alignItems:
                            "flex-start",
                        }}
                      >

                        <div>

                          <strong
                            style={{
                              color:
                                relationshipColor(
                                  edge.type
                                ),

                              fontSize:
                                "12px",
                            }}
                          >
                            {
                              relationName(
                                edge.type
                              )
                            }
                          </strong>


                          <p
                            style={{
                              marginTop: "4px",
                              fontSize: "12px",
                              lineHeight: "1.5",
                              opacity: 0.8,
                            }}
                          >
                            {
                              edge.reason
                              ??
                              edge.label
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
                              display:
                                "block",

                              color:
                                relationshipColor(
                                  edge.type
                                ),
                            }}
                          >
                            {
                              edge.strength
                            }%
                          </strong>


                          <span
                            style={{
                              fontSize:
                                "9px",

                              opacity:
                                0.6,
                            }}
                          >
                            {
                              edge.level
                            }
                          </span>

                        </div>

                      </div>


                      {
                        source
                        &&
                        target
                        &&
                        (

                          <div
                            style={{
                              display: "flex",
                              alignItems: "center",
                              flexWrap: "wrap",
                              gap: "7px",
                              marginTop: "11px",
                            }}
                          >

                            <button
                              type="button"
                              onClick={() =>
                                onOpenEvidence(
                                  source.subtitle
                                )
                              }
                              style={{
                                padding:
                                  "6px 9px",

                                border:
                                  "1px solid var(--border)",

                                borderRadius:
                                  "999px",

                                background:
                                  "rgba(255,255,255,0.025)",

                                fontSize:
                                  "10px",
                              }}
                            >
                              {
                                source.subtitle
                              }
                            </button>


                            <span
                              style={{
                                opacity:
                                  0.45,
                              }}
                            >
                              ↔
                            </span>


                            <button
                              type="button"
                              onClick={() =>
                                onOpenEvidence(
                                  target.subtitle
                                )
                              }
                              style={{
                                padding:
                                  "6px 9px",

                                border:
                                  "1px solid var(--border)",

                                borderRadius:
                                  "999px",

                                background:
                                  "rgba(255,255,255,0.025)",

                                fontSize:
                                  "10px",
                              }}
                            >
                              {
                                target.subtitle
                              }
                            </button>

                          </div>

                        )
                      }


                      {
                        edge.indicator_type
                        &&
                        edge.indicator_value
                        &&
                        (

                          <div
                            style={{
                              marginTop:
                                "10px",

                              padding:
                                "8px 9px",

                              borderRadius:
                                "9px",

                              background:
                                "rgba(0,0,0,0.16)",
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

                                opacity:
                                  0.55,
                              }}
                            >
                              {
                                edge.indicator_type
                              }
                            </span>


                            <code
                              style={{
                                display:
                                  "block",

                                marginTop:
                                  "4px",

                                fontSize:
                                  "10px",

                                wordBreak:
                                  "break-all",
                              }}
                            >
                              {
                                edge.indicator_value
                              }
                            </code>

                          </div>

                        )
                      }


                      <button
                        type="button"
                        onClick={() =>
                          onOpenEdge(
                            edge
                          )
                        }
                        style={{
                          marginTop:
                            "11px",

                          width:
                            "100%",
                        }}
                      >
                        Open in Evidence Graph
                      </button>

                    </div>

                  );
                }
              )
            }

          </div>

        )
      }


      {
        relatedClusters.length > 0
        &&
        (

          <div
            style={{
              marginTop:
                "16px",
            }}
          >

            <span className="eyebrow">
              RELATED CLUSTERS
            </span>


            <div
              style={{
                display:
                  "grid",

                gap:
                  "8px",

                marginTop:
                  "8px",
              }}
            >

              {
                relatedClusters.map(
                  (cluster) => {

                    const matchingMembers =
                      cluster.members.filter(
                        (member) =>
                          referencedCodes.has(
                            member.evidence_code
                          )
                      );


                    return (

                      <button
                        type="button"
                        key={
                          cluster.cluster_id
                        }
                        onClick={() =>
                          onOpenCluster(
                            cluster
                          )
                        }
                        style={{
                          textAlign:
                            "left",

                          padding:
                            "12px",

                          border:
                            "1px solid var(--border)",

                          borderRadius:
                            "12px",

                          background:
                            "rgba(165,140,255,0.045)",
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
                          }}
                        >

                          <div>

                            <strong>
                              {
                                cluster.cluster_id
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
                                  0.65,
                              }}
                            >
                              {
                                cluster.member_count
                              }
                              {" artifacts · "}
                              {
                                cluster.relationship_count
                              }
                              {" relationships"}
                            </span>

                          </div>


                          <strong
                            style={{
                              color:
                                "#a58cff",
                            }}
                          >
                            {
                              cluster.average_strength
                            }%
                          </strong>

                        </div>


                        <div
                          style={{
                            marginTop:
                              "8px",

                            fontSize:
                              "10px",

                            opacity:
                              0.7,
                          }}
                        >
                          Referenced here:{" "}

                          {
                            matchingMembers
                              .map(
                                (member) =>
                                  member.evidence_code
                              )
                              .join(
                                ", "
                              )
                          }
                        </div>


                        <div
                          style={{
                            marginTop:
                              "7px",

                            fontSize:
                              "10px",

                            opacity:
                              0.65,
                          }}
                        >
                          {
                            cluster.relation_types
                              .map(
                                relationName
                              )
                              .join(
                                " · "
                              )
                          }
                        </div>


                        <div
                          style={{
                            marginTop:
                              "9px",

                            fontSize:
                              "10px",

                            color:
                              "#9dd4ff",

                            fontWeight:
                              700,
                          }}
                        >
                          Open cluster in graph →
                        </div>

                      </button>

                    );
                  }
                )
              }

            </div>

          </div>

        )
      }


      <p
        style={{
          marginTop: "10px",
          fontSize: "10px",
          lineHeight: "1.5",
          opacity: 0.5,
        }}
      >
        These cards come from SYNAPSE&apos;s deterministic
        evidence graph, not from relationships invented by
        the language model.
      </p>

    </div>

  );
}
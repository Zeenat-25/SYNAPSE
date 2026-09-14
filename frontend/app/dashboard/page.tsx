"use client";

import Link from "next/link";
import {
  useEffect,
  useState,
} from "react";

import {
  deleteCase,
  getCases,
} from "@/lib/api";

import type {
  ForensicCase,
} from "@/lib/types";


export default function HomePage() {
  const [
    cases,
    setCases,
  ] = useState<ForensicCase[]>([]);

  const [
    loading,
    setLoading,
  ] = useState(true);

  const [
    error,
    setError,
  ] = useState("");


  async function loadCases() {
    try {
      setError("");

      const result =
        await getCases();

      setCases(result);

    } catch (error) {

      setError(
        error instanceof Error
          ? error.message
          : "Unable to load forensic cases."
      );

    } finally {

      setLoading(false);
    }
  }


  useEffect(() => {
    void loadCases();
  }, []);


  async function handleDelete(
    caseId: number,
    caseName: string
  ) {

    const confirmed =
      window.confirm(
        `Delete "${caseName}"?`
      );

    if (!confirmed) {
      return;
    }


    try {

      await deleteCase(
        caseId
      );

      setCases(
        (current) =>
          current.filter(
            (item) =>
              item.id !== caseId
          )
      );

    } catch (error) {

      window.alert(
        error instanceof Error
          ? error.message
          : "Unable to delete case."
      );
    }
  }


  const activeCases =
    cases.filter(
      (item) =>
        item.status === "ACTIVE"
    ).length;


  return (
    <main className="page">

      <header className="topbar">

        <div className="brand">

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

        </div>


        <div className="status">

          <span />

          FORENSIC CORE ONLINE

        </div>

      </header>


      <section className="dashboard">

        <div className="hero">

          <div>

            <span className="eyebrow">
              INVESTIGATION COMMAND
            </span>

            <h1>
              Forensic Cases
            </h1>

            <p>
              Create and manage digital
              forensic investigations.
            </p>

          </div>


          <Link
            href="/cases/new"
            className="primaryButton"
          >
            + New Case
          </Link>

        </div>


        <section className="stats">

          <article>

            <span>
              TOTAL CASES
            </span>

            <strong>
              {cases.length}
            </strong>

          </article>


          <article>

            <span>
              ACTIVE
            </span>

            <strong>
              {activeCases}
            </strong>

          </article>


          <article>

            <span>
              EVIDENCE
            </span>

            <strong>
              —
            </strong>

            <small>
              Phase 02
            </small>

          </article>


          <article>

            <span>
              BLIND SPOTS
            </span>

            <strong>
              —
            </strong>

            <small>
              Future engine
            </small>

          </article>

        </section>


        <section className="caseSection">

          <div className="sectionHeader">

            <div>

              <span className="eyebrow">
                CASE DATABASE
              </span>

              <h2>
                Investigations
              </h2>

            </div>


            <button
              type="button"
              className="ghostButton"
              onClick={() => {

                setLoading(true);

                void loadCases();

              }}
            >
              Refresh
            </button>

          </div>


          {loading && (

            <div className="emptyState">
              Loading forensic cases...
            </div>

          )}


          {!loading &&
            error && (

            <div className="errorState">

              <strong>
                Backend unavailable
              </strong>

              <p>
                {error}
              </p>

            </div>

          )}


          {!loading &&
            !error &&
            cases.length === 0 && (

            <div className="emptyState">

              <h3>
                No forensic cases yet
              </h3>

              <p>
                Create your first
                SYNAPSE investigation.
              </p>

              <Link
                href="/cases/new"
                className="primaryButton"
              >
                Create First Case
              </Link>

            </div>

          )}


          {!loading &&
            !error &&
            cases.length > 0 && (

            <div className="caseGrid">

              {cases.map(
                (forensicCase) => (

                <article
                  className="caseCard"
                  key={forensicCase.id}
                >

                  <div className="caseTop">

                    <span className="caseCode">

                      {
                        forensicCase.case_code
                      }

                    </span>


                    <span className="activeBadge">

                      ●{" "}
                      {
                        forensicCase.status
                      }

                    </span>

                  </div>


                  <h3>
                    {
                      forensicCase.name
                    }
                  </h3>


                  <p>

                    {
                      forensicCase.description
                      ||
                      "No description provided."
                    }

                  </p>


                  <div className="caseInfo">

                    <div>

                      <span>
                        TYPE
                      </span>

                      <strong>
                        {
                          forensicCase.case_type
                        }
                      </strong>

                    </div>


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

                  </div>


                  <div className="caseActions">

                    <Link
                      href={
                        `/cases/${forensicCase.id}`
                      }
                      className="openButton"
                    >
                      Open Investigation →
                    </Link>


                    <button
                      type="button"
                      className="deleteButton"
                      onClick={() =>
                        void handleDelete(
                          forensicCase.id,
                          forensicCase.name
                        )
                      }
                    >
                      Delete
                    </button>

                  </div>

                </article>

              ))}

            </div>

          )}

        </section>

      </section>

    </main>
  );
}
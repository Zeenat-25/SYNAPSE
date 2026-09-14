"use client";

import Link from "next/link";

import {
  FormEvent,
  useState,
} from "react";

import {
  useRouter,
} from "next/navigation";

import {
  createCase,
} from "@/lib/api";


export default function NewCasePage() {
  const router = useRouter();

  const [
    name,
    setName,
  ] = useState("");

  const [
    caseType,
    setCaseType,
  ] = useState(
    "Endpoint Investigation"
  );

  const [
    investigator,
    setInvestigator,
  ] = useState("");

  const [
    description,
    setDescription,
  ] = useState("");

  const [
    saving,
    setSaving,
  ] = useState(false);

  const [
    error,
    setError,
  ] = useState("");


  async function handleSubmit(
    event: FormEvent<HTMLFormElement>
  ) {
    event.preventDefault();

    if (name.trim().length < 2) {
      setError(
        "Enter a valid case name."
      );

      return;
    }

    setSaving(true);
    setError("");

    try {
      const created =
        await createCase({
          name: name.trim(),
          case_type:
            caseType.trim(),
          description:
            description.trim(),
          investigator:
            investigator.trim()
            || "Local Analyst",
        });

      router.push(
        `/cases/${created.id}`
      );
    } catch (error) {
      setError(
        error instanceof Error
          ? error.message
          : "Unable to create case."
      );

      setSaving(false);
    }
  }


  return (
    <main className="formPage">

      <Link
        href="/"
        className="backLink"
      >
        ← Back to Cases
      </Link>


      <div className="formIntro">

        <span className="eyebrow">
          NEW INVESTIGATION
        </span>

        <h1>
          Create Forensic Case
        </h1>

      </div>


      <form
        className="caseForm"
        onSubmit={handleSubmit}
      >

        <label>
          Case Name

          <input
            value={name}
            onChange={(event) =>
              setName(
                event.target.value
              )
            }
            placeholder="Operation Glasswire"
          />
        </label>


        <label>
          Investigation Type

          <select
            value={caseType}
            onChange={(event) =>
              setCaseType(
                event.target.value
              )
            }
          >
            <option>
              Endpoint Investigation
            </option>

            <option>
              Malware Investigation
            </option>

            <option>
              Network Investigation
            </option>

            <option>
              Incident Response
            </option>

            <option>
              Insider Threat
            </option>
          </select>
        </label>


        <label>
          Investigator

          <input
            value={investigator}
            onChange={(event) =>
              setInvestigator(
                event.target.value
              )
            }
            placeholder="Investigator name"
          />
        </label>


        <label>
          Description

          <textarea
            rows={6}
            value={description}
            onChange={(event) =>
              setDescription(
                event.target.value
              )
            }
            placeholder="Describe the investigation..."
          />
        </label>


        {error && (
          <div className="formError">
            {error}
          </div>
        )}


        <button
          className="primaryButton"
          type="submit"
          disabled={saving}
        >
          {saving
            ? "Creating..."
            : "Create Investigation"}
        </button>

      </form>

    </main>
  );
}
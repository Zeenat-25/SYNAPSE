import Link from "next/link";
import styles from "./portal.module.css";


/* =========================================================
   ICONS
========================================================= */

function ArrowIcon() {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M5 12H19"
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinecap="round"
      />
      <path
        d="M14 7L19 12L14 17"
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}


function DocumentIcon() {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M7 3H14L19 8V21H7V3Z"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <path
        d="M14 3V8H19"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <path
        d="M10 12H16"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
      <path
        d="M10 16H16"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
    </svg>
  );
}


function AnalysisIcon() {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <circle
        cx="11"
        cy="11"
        r="6"
        stroke="currentColor"
        strokeWidth="1.5"
      />
      <path
        d="M16 16L21 21"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
      <path
        d="M8.5 11H13.5"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
      <path
        d="M11 8.5V13.5"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
    </svg>
  );
}


function GraphIcon() {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <circle
        cx="6"
        cy="12"
        r="2"
        stroke="currentColor"
        strokeWidth="1.5"
      />
      <circle
        cx="17"
        cy="6"
        r="2"
        stroke="currentColor"
        strokeWidth="1.5"
      />
      <circle
        cx="18"
        cy="17"
        r="2"
        stroke="currentColor"
        strokeWidth="1.5"
      />
      <path
        d="M8 11L15 7"
        stroke="currentColor"
        strokeWidth="1.5"
      />
      <path
        d="M8 13L16 16"
        stroke="currentColor"
        strokeWidth="1.5"
      />
    </svg>
  );
}


function CoverageIcon() {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M5 19V12"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
      <path
        d="M10 19V7"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
      <path
        d="M15 19V10"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
      <path
        d="M20 19V4"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
    </svg>
  );
}


function LinkedInIcon() {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <rect
        x="3"
        y="3"
        width="18"
        height="18"
        rx="3"
        stroke="currentColor"
        strokeWidth="1.5"
      />
      <path
        d="M8 10V17"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
      <path
        d="M8 7V7.1"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
      />
      <path
        d="M12 17V13.5C12 11.8 13 10.8 14.4 10.8C15.9 10.8 16.5 11.8 16.5 13.5V17"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
    </svg>
  );
}


function GitHubIcon() {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M9 19C5.5 20 5.5 17 4 17M14 21V18.2C14 17.3 14.1 16.8 13.6 16.3C16.4 16 19.3 14.9 19.3 10.1C19.3 8.8 18.8 7.7 18 6.8C18.1 6.5 18.5 5.1 17.8 3.7C17.8 3.7 16.7 3.4 14 5.1C11.9 4.5 9.7 4.5 7.6 5.1C4.9 3.4 3.8 3.7 3.8 3.7C3.1 5.1 3.5 6.5 3.6 6.8C2.8 7.7 2.3 8.8 2.3 10.1C2.3 14.9 5.2 16 8 16.3C7.6 16.7 7.4 17.3 7.4 18.2V21"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}


function MailIcon() {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <rect
        x="3"
        y="5"
        width="18"
        height="14"
        rx="2"
        stroke="currentColor"
        strokeWidth="1.5"
      />
      <path
        d="M4 7L12 13L20 7"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}


/* =========================================================
   DATA
========================================================= */

const features = [
  {
    number: "01",
    title: "Evidence Intelligence",
    description:
      "Register, verify and inspect digital evidence with cryptographic integrity.",
    icon: <DocumentIcon />,
  },
  {
    number: "02",
    title: "Forensic Triage",
    description:
      "Combine PE machine-learning analysis with deterministic artifact examination.",
    icon: <AnalysisIcon />,
  },
  {
    number: "03",
    title: "Blind Spot Detection",
    description:
      "Surface important evidence that carries risk but may have received too little review.",
    icon: <GraphIcon />,
  },
  {
    number: "04",
    title: "Investigation Coverage",
    description:
      "Measure observable investigation coverage and understand where review remains incomplete.",
    icon: <CoverageIcon />,
  },
];


const workflow = [
  {
    number: "01",
    title: "Ingest",
    text: "Register evidence and preserve integrity.",
    icon: <DocumentIcon />,
  },
  {
    number: "02",
    title: "Analyze",
    text: "Run artifact-specific forensic triage.",
    icon: <AnalysisIcon />,
  },
  {
    number: "03",
    title: "Correlate",
    text: "Connect evidence using observable relationships.",
    icon: <GraphIcon />,
  },
  {
    number: "04",
    title: "Review",
    text: "Measure coverage and identify gaps.",
    icon: <CoverageIcon />,
  },
  {
    number: "05",
    title: "Report",
    text: "Produce structured forensic reports.",
    icon: <DocumentIcon />,
  },
];


/* =========================================================
   PAGE
========================================================= */

export default function Home() {
  return (
    <main className={styles.page}>

      {/* =================================================
          NAVBAR
      ================================================= */}

      <header className={styles.header}>
        <div className={styles.headerInner}>

          <Link
            href="/"
            className={styles.brand}
          >
            <img
              src="/synapse-logo.png"
              alt="SYNAPSE Human-Aware Forensics"
            />
          </Link>


          <nav className={styles.nav}>
            <a href="#home">
              Home
            </a>

            <a href="#features">
              Features
            </a>

            <a href="#why">
              Why SYNAPSE
            </a>

            <a href="#workflow">
              Workflow
            </a>

            <a href="#contact">
              Contact
            </a>
          </nav>


          <Link
            href="/dashboard"
            className={styles.navLaunch}
          >
            Launch SYNAPSE

            <ArrowIcon />
          </Link>

        </div>
      </header>


      {/* =================================================
          HERO
      ================================================= */}

      <section
        id="home"
        className={styles.hero}
      >

        <div className={styles.heroInner}>

          <div className={styles.heroCopy}>

            <span className={styles.eyebrow}>
              HUMAN-AWARE CYBER FORENSICS
            </span>


            <h1>
              Investigate deeper.
              <span>
                Miss less.
              </span>
            </h1>


            <p className={styles.heroText}>
              SYNAPSE helps investigators analyze digital
              evidence, understand forensic risk, track
              investigation coverage, and surface important
              evidence that may have been overlooked.
            </p>


            <div className={styles.heroActions}>

              <Link
                href="/dashboard"
                className={styles.primaryButton}
              >
                Launch SYNAPSE
                <ArrowIcon />
              </Link>


              <a
                href="#features"
                className={styles.secondaryButton}
              >
                Explore Platform
              </a>

            </div>


            <div className={styles.heroMeta}>
              <span>
                EVIDENCE-FIRST
              </span>

              <i />

              <span>
                HUMAN-AWARE
              </span>

              <i />

              <span>
                AUDITABLE
              </span>
            </div>

          </div>


          {/* =============================================
              PRODUCT MOCKUP
          ============================================= */}

          <div className={styles.productVisual}>

            <div className={styles.productGlow} />


            <div className={styles.productWindow}>

              <div className={styles.productTopbar}>

                <div className={styles.productBrand}>
                  <img
                    src="/synapse-logo.png"
                    alt=""
                  />
                </div>


                <div className={styles.fakeSearch}>
                  Search cases, evidence, keywords...
                </div>


                <div className={styles.fakeUser}>
                  ZA
                </div>

              </div>


              <div className={styles.productBody}>

                <aside className={styles.fakeSidebar}>

                  <div className={styles.fakeNavActive}>
                    Overview
                  </div>

                  <div>
                    Cases
                  </div>

                  <div>
                    Evidence
                  </div>

                  <div>
                    Evidence Graph
                  </div>

                  <div>
                    Forensic Triage
                  </div>

                  <div>
                    AI Analyst
                  </div>

                  <div>
                    Coverage
                  </div>

                  <div>
                    Timeline
                  </div>

                  <div>
                    Reports
                  </div>

                </aside>


                <section className={styles.fakeWorkspace}>

                  <div className={styles.fakeHeading}>

                    <div>
                      <span>
                        INVESTIGATION COMMAND
                      </span>

                      <h2>
                        Forensic Cases
                      </h2>

                      <p>
                        Create and manage digital forensic investigations.
                      </p>
                    </div>


                    <button>
                      + New Case
                    </button>

                  </div>


                  <div className={styles.fakeStats}>

                    <div>
                      <span>
                        TOTAL CASES
                      </span>

                      <strong>
                        6
                      </strong>
                    </div>


                    <div>
                      <span>
                        ACTIVE
                      </span>

                      <strong>
                        3
                      </strong>
                    </div>


                    <div>
                      <span>
                        EVIDENCE
                      </span>

                      <strong>
                        248
                      </strong>
                    </div>


                    <div>
                      <span>
                        BLIND SPOTS
                      </span>

                      <strong>
                        2
                      </strong>
                    </div>

                  </div>


                  <div className={styles.fakeContentGrid}>

                    <div className={styles.fakeCases}>

                      <div className={styles.fakeSectionTitle}>
                        Recent Investigations
                      </div>


                      <div className={styles.fakeCaseRow}>
                        <div>
                          <strong>
                            Operation Glasswire
                          </strong>

                          <span>
                            CF-2026-BE5041
                          </span>
                        </div>

                        <b>
                          ACTIVE
                        </b>
                      </div>


                      <div className={styles.fakeCaseRow}>
                        <div>
                          <strong>
                            Rogue Access
                          </strong>

                          <span>
                            CF-2026-BE5040
                          </span>
                        </div>

                        <b className={styles.analysisBadge}>
                          ANALYSIS
                        </b>
                      </div>


                      <div className={styles.fakeCaseRow}>
                        <div>
                          <strong>
                            Data Exfiltration
                          </strong>

                          <span>
                            CF-2026-BE5039
                          </span>
                        </div>

                        <b className={styles.triageBadge}>
                          TRIAGE
                        </b>
                      </div>

                    </div>


                    <div className={styles.fakeActions}>

                      <div className={styles.fakeSectionTitle}>
                        Quick Actions
                      </div>


                      <div className={styles.fakePrimaryAction}>
                        New Case
                      </div>

                      <div>
                        Upload Evidence
                      </div>

                      <div>
                        Run AI Triage
                      </div>

                      <div>
                        Generate Report
                      </div>

                    </div>

                  </div>

                </section>

              </div>


              <div className={styles.productFooter}>
                <span>
                  Same data. A smarter perspective.
                </span>

                <span>
                  PEOPLE · DATA · BEHAVIOR · TRUTH
                </span>
              </div>

            </div>

          </div>

        </div>

      </section>


      {/* =================================================
          FEATURES
      ================================================= */}

      <section
        id="features"
        className={styles.section}
      >

        <div className={styles.sectionTop}>

          <div>
            <span className={styles.eyebrow}>
              WHAT SYNAPSE DOES
            </span>

            <h2>
              Purpose-built for modern investigations.
            </h2>
          </div>


          <p>
            From evidence registration to final reporting,
            SYNAPSE supports the forensic workflow with a
            focus on human-aware analysis.
          </p>

        </div>


        <div className={styles.featuresGrid}>

          {
            features.map(
              (feature) => (

                <article
                  key={feature.number}
                  className={styles.featureCard}
                >

                  <div className={styles.featureIcon}>
                    {feature.icon}
                  </div>


                  <span className={styles.featureNumber}>
                    {feature.number}
                  </span>


                  <h3>
                    {feature.title}
                  </h3>


                  <p>
                    {feature.description}
                  </p>

                </article>

              )
            )
          }

        </div>

      </section>


      {/* =================================================
          WHY SYNAPSE
      ================================================= */}

      <section
        id="why"
        className={styles.whySection}
      >

        <div className={styles.whyInner}>

          <div className={styles.whyCopy}>

            <span className={styles.eyebrow}>
              WHY SYNAPSE
            </span>


            <h2>
              Important evidence
              <br />
              shouldn&apos;t disappear
              <span>
                in the noise.
              </span>
            </h2>


            <p>
              Traditional forensic workflows focus on
              what the evidence contains. SYNAPSE also
              asks:
            </p>


            <blockquote>
              “Did the investigator actually cover the
              evidence that mattered?”
            </blockquote>


            <div className={styles.formula}>
              <span>
                Forensic Risk
              </span>

              <i>
                ×
              </i>

              <span>
                Human Review Coverage
              </span>

              <b>
                →
              </b>

              <strong>
                Blind Spot Detection
              </strong>
            </div>

          </div>


          <div className={styles.whyVisual}>

            <div className={styles.visualGrid} />

            <div className={styles.visualNodeOne}>
              <span>
                PEOPLE
              </span>
            </div>

            <div className={styles.visualNodeTwo}>
              <span>
                DATA
              </span>
            </div>

            <div className={styles.visualNodeThree}>
              <span>
                BEHAVIOR
              </span>
            </div>

            <div className={styles.visualNodeFour}>
              <span>
                TRUTH
              </span>
            </div>

            <div className={styles.visualTraceOne} />
            <div className={styles.visualTraceTwo} />
            <div className={styles.visualTraceThree} />

          </div>

        </div>

      </section>


      {/* =================================================
          WORKFLOW
      ================================================= */}

      <section
        id="workflow"
        className={styles.section}
      >

        <div className={styles.workflowHeading}>

          <div>
            <span className={styles.eyebrow}>
              BUILT FOR INVESTIGATION
            </span>

            <h2>
              A clear path from evidence to insight.
            </h2>
          </div>


          <p>
            Structured. Transparent. Defensible.
          </p>

        </div>


        <div className={styles.workflowGrid}>

          {
            workflow.map(
              (
                item,
                index
              ) => (

                <article
                  key={item.number}
                  className={styles.workflowStep}
                >

                  <div className={styles.workflowIcon}>
                    {item.icon}
                  </div>


                  <div>
                    <span>
                      {item.number}
                    </span>

                    <h3>
                      {item.title}
                    </h3>

                    <p>
                      {item.text}
                    </p>
                  </div>


                  {
                    index < workflow.length - 1
                    &&
                    (
                      <ArrowIcon />
                    )
                  }

                </article>

              )
            )
          }

        </div>

      </section>


      {/* =================================================
          CTA
      ================================================= */}

      <section className={styles.ctaSection}>

        <div className={styles.cta}>

          <div>

            <span className={styles.eyebrow}>
              ENTER THE PLATFORM
            </span>

            <h2>
              Start your forensic investigation.
            </h2>

          </div>


          <div className={styles.ctaAction}>

            <Link
              href="/dashboard"
              className={styles.primaryButton}
            >
              Launch SYNAPSE
              <ArrowIcon />
            </Link>


            <small>
              Same data. A safer tomorrow.
            </small>

          </div>

        </div>

      </section>


      {/* =================================================
          FOOTER
      ================================================= */}

      <footer
        id="contact"
        className={styles.footer}
      >

        <div className={styles.footerInner}>

          <div className={styles.footerBrand}>
            <img
              src="/synapse-logo.png"
              alt="SYNAPSE"
            />
          </div>


          <div className={styles.footerLinks}>
            <a href="#home">
              Home
            </a>

            <a href="#features">
              Features
            </a>

            <a href="#why">
              Why SYNAPSE
            </a>

            <a href="#contact">
              Contact
            </a>
          </div>


          <div className={styles.developerBlock}>

            <div>
              <span>
                DEVELOPED BY
              </span>

              <strong>
                Zeenat Ansari
              </strong>
            </div>


            <div className={styles.socials}>

              <a
                href="https://www.linkedin.com/in/zeenat-ansari-ab566b353/"
                target="_blank"
                rel="noreferrer"
                aria-label="LinkedIn"
              >
                <LinkedInIcon />
              </a>


              <a
                href="https://github.com/Zeenat-25"
                target="_blank"
                rel="noreferrer"
                aria-label="GitHub"
              >
                <GitHubIcon />
              </a>


              <a
                href="mailto:libraskingdom@gmail.com"
                aria-label="Email"
              >
                <MailIcon />
              </a>

            </div>

          </div>

        </div>


        <div className={styles.footerBottom}>

          <span>
            © 2026 SYNAPSE
          </span>

          <span>
            Human-Aware Forensics
          </span>

          <span>
            Built for a safer digital world.
          </span>

        </div>

      </footer>

    </main>
  );
}
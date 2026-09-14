import styles from "./loading.module.css";


export default function DashboardLoading() {
  return (
    <main className={styles.loadingScreen}>

      <div className={styles.loader}>

        <div className={styles.logoWrap}>

          <img
            src="/synapse-mark.png"
            alt="SYNAPSE"
            className={styles.logo}
          />

          <div className={styles.logoGlow} />

        </div>


        <div className={styles.copy}>

          <strong>
            SYNAPSE
          </strong>

          <span>
            Initializing investigation workspace
          </span>

        </div>


        <div className={styles.progress}>
          <span />
        </div>


        <div className={styles.status}>
          HUMAN-AWARE FORENSICS
        </div>

      </div>

    </main>
  );
}
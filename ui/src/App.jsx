import React, { useMemo, useState } from "react";
import { downloadUrl, generateSample, getStatus, startRun } from "./api.js";

const MODE_OPTIONS = [
  { value: "simple", label: "Single-threaded" },
  { value: "mt", label: "Multi-threaded" },
];

const DEFAULT_RULES = {
  blocked_ips: "",
  blocked_apps: "youtube",
  blocked_domains: "facebook",
};

function parseList(value) {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

export default function App() {
  const [file, setFile] = useState(null);
  const [mode, setMode] = useState("simple");
  const [lbs, setLbs] = useState(2);
  const [fps, setFps] = useState(2);
  const [throttleMs, setThrottleMs] = useState(0);
  const [rules, setRules] = useState(DEFAULT_RULES);
  const [randomizeSample, setRandomizeSample] = useState(true);
  const [sampleSize, setSampleSize] = useState(3);
  const [sampleId, setSampleId] = useState("");
  const [sampleCount, setSampleCount] = useState(0);
  const [jobId, setJobId] = useState(null);
  const [status, setStatus] = useState("idle");
  const [error, setError] = useState("");
  const [report, setReport] = useState(null);
  const [progress, setProgress] = useState(null);

  const canSubmit = useMemo(
    () => (file || sampleId) && status !== "running",
    [file, sampleId, status]
  );

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");
    setReport(null);

    if (!file && !sampleId) {
      setError("Select a PCAP file or generate a sample first.");
      return;
    }

    const rulesPayload = {
      blocked_ips: parseList(rules.blocked_ips),
      blocked_apps: parseList(rules.blocked_apps),
      blocked_domains: parseList(rules.blocked_domains),
    };

    const formData = new FormData();
    if (file) {
      formData.append("file", file);
    }
    if (sampleId && !file) {
      formData.append("sample_id", sampleId);
    }
    formData.append("mode", mode);
    formData.append("lbs", String(lbs));
    formData.append("fps", String(fps));
    formData.append("throttle_ms", String(throttleMs));
    formData.append("rules", JSON.stringify(rulesPayload));

    try {
      setStatus("running");
      const { job_id } = await startRun(formData);
      setJobId(job_id);
      pollStatus(job_id);
    } catch (err) {
      setStatus("idle");
      setError(err.message || "Failed to start job");
    }
  }

  async function handleSampleRun() {
    setError("");
    setReport(null);

    if (status === "running") {
      return;
    }

    const rulesPayload = {
      blocked_ips: parseList(rules.blocked_ips),
      blocked_apps: parseList(rules.blocked_apps),
      blocked_domains: parseList(rules.blocked_domains),
    };

    try {
      const data = await generateSample({
        randomize: String(randomizeSample),
        size_factor: String(sampleSize),
      });
      setSampleId(data.sample_id);
      setSampleCount(data.packet_count || 0);
    } catch (err) {
      setStatus("idle");
      setError(err.message || "Failed to start sample job");
    }
  }

  async function pollStatus(id) {
    try {
      const data = await getStatus(id);
      setStatus(data.status);
      if (data.progress) {
        setProgress(data.progress);
      }
      if (data.status === "done") {
        setReport(data.report);
        setProgress(null);
      } else if (data.status === "error") {
        setError(data.error || "Job failed");
        setProgress(null);
      } else {
        setTimeout(() => pollStatus(id), 1000);
      }
    } catch (err) {
      setError(err.message || "Failed to fetch status");
      setStatus("idle");
    }
  }

  return (
    <div className="app-shell">
      <header className="app-header">
        <div>
          <p className="eyebrow">Deep Packet Inspection</p>
          <h1>DPI Engine Control Room</h1>
          <p className="subtitle">
            Upload a PCAP, choose rules, and inspect traffic classification.
          </p>
        </div>
        <div className="status-pill">
          <span className={`dot ${status}`} />
          {status.toUpperCase()}
        </div>
      </header>

      <section className="panel-grid">
        <form className="panel" onSubmit={handleSubmit}>
          <h2>Run Configuration</h2>

          <label className="field">
            <span>PCAP file</span>
            <input type="file" accept=".pcap" onChange={(e) => setFile(e.target.files[0])} />
          </label>

          {sampleId && (
            <p className="muted">Sample ready: {sampleCount} packets</p>
          )}

          <label className="field checkbox">
            <input
              type="checkbox"
              checked={randomizeSample}
              onChange={(e) => setRandomizeSample(e.target.checked)}
            />
            <span>Randomize sample domains</span>
          </label>

          <label className="field">
            <span>Sample size</span>
            <input
              type="range"
              min={1}
              max={6}
              value={sampleSize}
              onChange={(e) => setSampleSize(Number(e.target.value))}
            />
            <span className="hint">Size factor: {sampleSize}x</span>
          </label>

          <label className="field">
            <span>Throttle (ms per packet)</span>
            <input
              type="range"
              min={0}
              max={50}
              value={throttleMs}
              onChange={(e) => setThrottleMs(Number(e.target.value))}
            />
            <span className="hint">{throttleMs} ms</span>
          </label>

          <button className="secondary" type="button" onClick={handleSampleRun} disabled={status === "running"}>
            Generate sample PCAP
          </button>

          <div className="field">
            <span>Mode</span>
            <div className="segmented">
              {MODE_OPTIONS.map((option) => (
                <button
                  key={option.value}
                  type="button"
                  className={mode === option.value ? "active" : ""}
                  onClick={() => setMode(option.value)}
                >
                  {option.label}
                </button>
              ))}
            </div>
          </div>

          {mode === "mt" && (
            <div className="field row">
              <label>
                <span>Load balancers</span>
                <input
                  type="number"
                  min={1}
                  value={lbs}
                  onChange={(e) => setLbs(Number(e.target.value))}
                />
              </label>
              <label>
                <span>FPs per LB</span>
                <input
                  type="number"
                  min={1}
                  value={fps}
                  onChange={(e) => setFps(Number(e.target.value))}
                />
              </label>
            </div>
          )}

          <h3>Blocking Rules</h3>
          <label className="field">
            <span>Blocked apps (comma separated)</span>
            <input
              value={rules.blocked_apps}
              onChange={(e) => setRules({ ...rules, blocked_apps: e.target.value })}
              placeholder="youtube, tiktok"
            />
          </label>
          <label className="field">
            <span>Blocked domains (comma separated)</span>
            <input
              value={rules.blocked_domains}
              onChange={(e) => setRules({ ...rules, blocked_domains: e.target.value })}
              placeholder="facebook, instagram"
            />
          </label>
          <label className="field">
            <span>Blocked IPs (comma separated)</span>
            <input
              value={rules.blocked_ips}
              onChange={(e) => setRules({ ...rules, blocked_ips: e.target.value })}
              placeholder="192.168.1.50"
            />
          </label>

          <button className="primary" type="submit" disabled={!canSubmit}>
            {status === "running" ? "Running..." : "Run DPI"}
          </button>

          {error && <p className="error">{error}</p>}
        </form>

        <div className="panel report">
          <h2>Report</h2>
          {status === "running" && progress && (
            <div className="live-panel">
              <h3>Live Stats</h3>
              <div className="report-grid">
                <div>
                  <p className="label">Total packets</p>
                  <p className="value">{progress.total_packets}</p>
                </div>
                <div>
                  <p className="label">Forwarded</p>
                  <p className="value">{progress.forwarded}</p>
                </div>
                <div>
                  <p className="label">Dropped</p>
                  <p className="value">{progress.dropped}</p>
                </div>
                <div>
                  <p className="label">Bytes</p>
                  <p className="value">{progress.total_bytes}</p>
                </div>
              </div>
            </div>
          )}
          {!report && <p className="muted">Run a job to see results.</p>}
          {report && (
            <div>
              <div className="report-grid">
                <div>
                  <p className="label">Total packets</p>
                  <p className="value">{report.total_packets}</p>
                </div>
                <div>
                  <p className="label">Forwarded</p>
                  <p className="value">{report.forwarded}</p>
                </div>
                <div>
                  <p className="label">Dropped</p>
                  <p className="value">{report.dropped}</p>
                </div>
                <div>
                  <p className="label">Throughput</p>
                  <p className="value">
                    {report.performance?.packets_per_sec?.toFixed(2)} pkt/s
                  </p>
                </div>
              </div>

              <h3>Applications</h3>
              <ul className="list">
                {report.app_breakdown.map((app) => (
                  <li key={app.app}>
                    <span>{app.app}</span>
                    <span>{app.count} packets</span>
                  </li>
                ))}
              </ul>

              <h3>Detected Domains</h3>
              <ul className="list">
                {report.detected_domains.map((item) => (
                  <li key={item.domain}>
                    <span>{item.domain}</span>
                    <span>{item.app}</span>
                  </li>
                ))}
              </ul>

              <h3>Blocked Matches (Seen in Capture)</h3>
              <div className="blocked-grid">
                <div>
                  <p className="label">Apps</p>
                  <p className="value small">
                    {report.blocked_matches?.apps?.length ? report.blocked_matches.apps.join(", ") : "None"}
                  </p>
                </div>
                <div>
                  <p className="label">Domains</p>
                  {report.blocked_matches?.domains?.length ? (
                    <ul className="list compact">
                      {report.blocked_matches.domains.map((item) => (
                        <li key={item.domain}>
                          <span>{item.domain}</span>
                          <span>{item.app}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="value small">None</p>
                  )}
                </div>
                <div>
                  <p className="label">IPs</p>
                  <p className="value small">
                    {report.blocked_matches?.ips?.length ? report.blocked_matches.ips.join(", ") : "None"}
                  </p>
                </div>
              </div>

              {jobId && (
                <a className="secondary" href={downloadUrl(jobId)}>
                  Download filtered PCAP
                </a>
              )}
            </div>
          )}
        </div>
      </section>
    </div>
  );
}

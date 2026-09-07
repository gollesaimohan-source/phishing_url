import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import PageContainer from "../layouts/PageContainer.jsx";
import SummaryCard from "../components/SummaryCard.jsx";
import StatusBadge from "../components/StatusBadge.jsx";
import EmptyState from "../components/EmptyState.jsx";
import SkeletonCard from "../components/SkeletonCard.jsx";
import ErrorAlert from "../components/ErrorAlert.jsx";
import { formatDateTime } from "../utils/formatters.js";
import { formatRelativeTime } from "../utils/formatRelativeTime.js";
import {
  getDashboardSummary,
  getRecentScans,
  getRiskDistribution,
  getThreatFeed,
} from "../services/dashboardService.js";

const EMPTY_SUMMARY = {
  total_scans: 0,
  threats_detected: 0,
  safe_urls: 0,
  known_threats: 0,
};

const MODULE_CARDS = [
  {
    id: "url",
    title: "URL & Web Scanner",
    desc: "Inspect suspicious domains, short links, and phishing portals.",
    icon: "bi-globe2",
    color: "var(--color-accent)",
  },
  {
    id: "text",
    title: "Text & Fake News",
    desc: "Detect scam SMS, phishing emails, and fake news articles.",
    icon: "bi-card-heading",
    color: "var(--color-info)",
  },
  {
    id: "image",
    title: "AI Image & Deepfake",
    desc: "Analyze photos, AI generator signatures, and metadata.",
    icon: "bi-image",
    color: "var(--color-secondary)",
  },
  {
    id: "video",
    title: "Video & Audio Forensics",
    desc: "Evaluate deepfake video anchors and synthetic voice clips.",
    icon: "bi-camera-video",
    color: "var(--color-danger)",
  },
];

export default function Dashboard() {
  const [summary, setSummary] = useState(EMPTY_SUMMARY);
  const [recentScans, setRecentScans] = useState([]);
  const [riskDistribution, setRiskDistribution] = useState({});
  const [threatFeed, setThreatFeed] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    let isMounted = true;

    async function loadDashboard() {
      setIsLoading(true);
      setError("");

      try {
        const [summaryResponse, scansResponse, distributionResponse, feedResponse] =
          await Promise.all([
            getDashboardSummary().catch(() => ({ data: EMPTY_SUMMARY })),
            getRecentScans().catch(() => ({ data: [] })),
            getRiskDistribution().catch(() => ({ data: {} })),
            getThreatFeed().catch(() => ({ data: [] })),
          ]);

        if (!isMounted) return;

        setSummary(summaryResponse.data || EMPTY_SUMMARY);
        setRecentScans(scansResponse.data || []);
        setRiskDistribution(distributionResponse.data || {});
        setThreatFeed(feedResponse.data || []);
      } catch (requestError) {
        if (!isMounted) return;
        setSummary(EMPTY_SUMMARY);
      } finally {
        if (isMounted) {
          setIsLoading(false);
        }
      }
    }

    loadDashboard();

    return () => {
      isMounted = false;
    };
  }, []);

  const summaryCards = useMemo(
    () => [
      {
        icon: "bi-search",
        title: "Total Scans",
        value: formatCount(summary.total_scans ?? 0),
        description: "Multi-modal scans processed",
        variant: "info",
      },
      {
        icon: "bi-exclamation-triangle",
        title: "Threats Flagged",
        value: formatCount(summary.threats_detected ?? 0),
        description: "Phishing & Deepfake alerts",
        variant: "danger",
      },
      {
        icon: "bi-shield-check",
        title: "Verified Safe",
        value: formatCount(summary.safe_urls ?? 0),
        description: "Authentic sources & links",
        variant: "success",
      },
      {
        icon: "bi-database-fill-gear",
        title: "Threat Intel DB",
        value: formatCount(summary.known_threats ?? 0),
        description: "Active fraud signatures",
        variant: "warning",
      },
    ],
    [summary],
  );

  return (
    <PageContainer
      title="Security Operations Dashboard"
      subtitle="Real-time multi-modal threat radar, scan telemetry & AI deepfake intelligence."
    >
      {error ? <ErrorAlert message={error} onDismiss={() => setError("")} /> : null}

      {/* Summary KPI Row */}
      <div className="row g-4 mb-5 dashboard-kpi-grid">
        {isLoading
          ? Array.from({ length: 4 }, (_, index) => (
              <div key={index} className="col-12 col-sm-6 col-lg-3">
                <SkeletonCard className="skeleton-kpi" rows={3} />
              </div>
            ))
          : summaryCards.map((card, idx) => (
              <div
                key={card.title}
                className="col-12 col-sm-6 col-lg-3 animate-fade-in"
                style={{ animationDelay: `${idx * 0.08}s` }}
              >
                <SummaryCard {...card} />
              </div>
            ))}
      </div>
      {Number(summary.total_scans ?? 0) === 0 ? (
        <div className="text-muted small mb-5">No scans yet - run your first scan.</div>
      ) : null}

      {/* Multi-Modal Module Direct Launchers */}
      <div className="dashboard-section-header">
        <i className="bi bi-cpu-fill" />
        <h3>AI Detection Modules</h3>
      </div>
      <div className="row g-4 mb-5 dashboard-module-grid">
        {MODULE_CARDS.map((module) => (
          <div key={module.id} className="col-12 col-sm-6 col-lg-3">
            <div
              className="dashboard-module-card glass-panel h-100 text-start"
              onClick={() => navigate("/scanner")}
            >
              <div
                className="dashboard-module-icon"
                style={{
                  background: `${module.color}15`,
                  color: module.color,
                  border: `1px solid ${module.color}30`,
                }}
              >
                <i className={`bi ${module.icon}`} />
              </div>
              <h4>{module.title}</h4>
              <p>{module.desc}</p>
              <div className="dashboard-module-link">
                <span>Launch Detector</span>
                <i className="bi bi-arrow-right" />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Recent Activity Table & Threat Feed */}
      <div className="row g-4 mb-5">
        <div className="col-12 col-lg-8 animate-fade-in" style={{ animationDelay: "0.3s" }}>
          <div className="dashboard-feed-panel glass-panel h-100 overflow-hidden">
            <div className="dashboard-panel-header">
              <div className="d-flex align-items-center">
                <i className="bi bi-clock-history me-2" />
                <h3>Live Activity Telemetry</h3>
              </div>
              <Link to="/history" className="dashboard-panel-link">
                View History <i className="bi bi-arrow-right ms-1" />
              </Link>
            </div>
            <div className="p-0">
              {isLoading ? (
                <SkeletonCard className="skeleton-table" rows={5} />
              ) : recentScans.length > 0 ? (
                <div className="table-responsive">
                  <table className="dashboard-table table align-middle mb-0">
                    <thead>
                      <tr>
                        <th className="ps-4 py-3">Payload / Target</th>
                        <th className="py-3">Mode</th>
                        <th className="py-3">Risk Level</th>
                        <th className="pe-4 py-3 text-end">Time</th>
                      </tr>
                    </thead>
                    <tbody>
                      {recentScans.map((scan, idx) => (
                        <tr key={scan.scan_id || idx}>
                          <td className="ps-4 py-3 text-truncate" style={{ maxWidth: "260px" }}>
                            {scan.input || "Target domain"}
                          </td>
                          <td className="py-3">
                            <span className="dashboard-kind-badge">
                              {scan.kind || "URL"}
                            </span>
                          </td>
                          <td className="py-3">
                            <StatusBadge status={scan.risk || "suspicious"} />
                          </td>
                          <td className="pe-4 py-3 text-end text-muted small">
                            <span title={formatDateTime(scan.created_at)}>
                              {formatRelativeTime(scan.created_at)}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="p-4 text-center text-muted">
                  <i className="bi bi-shield-check fs-2 text-info d-block mb-2" />
                  <p className="mb-0 small">Engine ready. Run scans from the Scanner page to see live telemetry here.</p>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Live Threat Intelligence Feed */}
        <div className="col-12 col-lg-4 animate-fade-in" style={{ animationDelay: "0.4s" }}>
          <div className="dashboard-feed-panel glass-panel h-100 overflow-hidden">
            <div className="dashboard-panel-header">
              <div className="d-flex align-items-center">
                <i className="bi bi-rss-fill me-2" />
                <h3>Threat Intelligence Feed</h3>
              </div>
            </div>
            <div className="dashboard-feed-list">
              {isLoading ? (
                <SkeletonCard className="skeleton-feed" rows={4} />
              ) : threatFeed.length > 0 ? (
                threatFeed.map((item, idx) => (
                  <div key={item.threat_id || item.domain || idx} className="dashboard-feed-item">
                    <div className="dashboard-feed-icon">
                      <i className="bi bi-bug-fill" />
                    </div>
                    <div>
                      <p>{item.domain || item.label || "Unknown domain"}</p>
                      <div className="dashboard-feed-meta">
                        <span className="dashboard-feed-risk">{(item.severity || "unknown").toUpperCase()}</span>
                        <span>• {item.classification || item.label || "Threat intelligence"}</span>
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                <EmptyState
                  icon="bi-rss"
                  title="No Threats Yet"
                  description="Threat intelligence will appear here after scans identify known risks."
                />
              )}
            </div>
          </div>
        </div>
      </div>
    </PageContainer>
  );
}

function formatCount(value) {
  return new Intl.NumberFormat().format(Number(value || 0));
}

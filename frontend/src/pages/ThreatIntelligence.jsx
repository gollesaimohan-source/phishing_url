import { useEffect, useState } from "react";
import PageContainer from "../layouts/PageContainer.jsx";
import { getDashboardSummary } from "../services/dashboardService.js";
import { getDomainThreat, getTopThreats } from "../services/threatService.js";
import ThreatIntelCard from "../components/ThreatIntelCard.jsx";
import LoadingSpinner from "../components/LoadingSpinner.jsx";
import ErrorAlert from "../components/ErrorAlert.jsx";
import EmptyState from "../components/EmptyState.jsx";
import { formatDateTime, riskBadgeClass } from "../utils/formatters.js";
import { formatRelativeTime } from "../utils/formatRelativeTime.js";

export default function ThreatIntelligence() {
  const [domain, setDomain] = useState("");
  const [record, setRecord] = useState(null);
  const [topThreats, setTopThreats] = useState([]);
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [searched, setSearched] = useState(false);
  const [summary, setSummary] = useState({ total_scans: 0, known_threats: 0 });

  useEffect(() => {
    getDashboardSummary()
      .then((response) => setSummary(response.data || { total_scans: 0, known_threats: 0 }))
      .catch(() => setSummary({ total_scans: 0, known_threats: 0 }));
  }, []);

  const quickStats = [
    { label: "Scans Processed", value: summary.total_scans ?? 0, detail: "stored investigations" },
    { label: "Known Threats", value: summary.known_threats ?? 0, detail: "tracked domains" },
  ];

  const lookupDomain = async (event) => {
    event.preventDefault();
    setError("");
    setRecord(null);
    setTopThreats([]);
    setIsLoading(true);
    setSearched(true);
    try {
      const response = await getDomainThreat(domain);
      if (response && response.data) {
        setRecord(response.data);
      } else {
        setError("No threat intelligence record found for this domain.");
      }
    } catch (requestError) {
      setError(requestError.message || "Domain lookup failed.");
    } finally {
      setIsLoading(false);
    }
  };

  const loadTopThreats = async () => {
    setError("");
    setRecord(null);
    setTopThreats([]);
    setIsLoading(true);
    setSearched(true);
    try {
      const response = await getTopThreats();
      setTopThreats(response.data || []);
    } catch (requestError) {
      setError(requestError.message || "Failed to load top threats.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <PageContainer
      title="Threat Intelligence"
      subtitle="Investigate domain reputation, malicious infrastructure, and active scam campaigns with a professional intelligence workflow."
    >
      <div className="threat-shell">
        <section className="glass-panel threat-hero">
          <div className="threat-hero-copy">
            <span className="section-kicker">Threat intelligence command center</span>
            <h2>Investigate suspicious infrastructure with explainable context.</h2>
            <p>
              ScamShield combines live lookup and historical telemetry so analysts can judge reputation,
              urgency, and follow-up action in a single view.
            </p>
          </div>
          <div className="threat-hero-stats">
            {quickStats.map((stat) => (
              <div key={stat.label} className="threat-stat-card">
                <strong>{stat.value}</strong>
                <span>{stat.label}</span>
                <small>{stat.detail}</small>
              </div>
            ))}
          </div>
        </section>

        <section className="glass-panel threat-lookup-panel">
          <form onSubmit={lookupDomain}>
            <div className="threat-lookup-field">
              <label htmlFor="threat-domain-input">Domain lookup</label>
              <div className="threat-input-group">
                <span>
                  <i className="bi bi-globe" />
                </span>
                <input
                  id="threat-domain-input"
                  value={domain}
                  onChange={(event) => setDomain(event.target.value)}
                  placeholder="e.g. malicious-site.com"
                  required
                  disabled={isLoading}
                />
              </div>
            </div>
            <div className="threat-actions">
              <button className="btn-premium-primary" type="submit" disabled={isLoading}>
                <i className="bi bi-search" />
                Lookup
              </button>
              <button className="btn-premium-secondary" type="button" onClick={loadTopThreats} disabled={isLoading}>
                <i className="bi bi-bar-chart-line" />
                Top threats
              </button>
            </div>
          </form>
        </section>

        {error ? <ErrorAlert message={error} onDismiss={() => setError("")} /> : null}

        {isLoading ? (
          <div className="glass-panel threat-loading-panel">
            <LoadingSpinner message="Searching global threat reputation databases..." />
          </div>
        ) : null}

        {record && !isLoading ? (
          <ThreatIntelCard threatIntel={record} domainName={record.domain} />
        ) : null}

        {topThreats.length > 0 && !isLoading ? (
          <section className="glass-panel threat-table-panel">
            <div className="threat-table-header">
              <div>
                <span className="section-kicker">Observed targets</span>
                <h3>Top threat targets in the live dataset</h3>
              </div>
              <span className="section-badge">Updated continuously</span>
            </div>
            <div className="table-responsive">
              <table className="threat-table">
                <thead>
                  <tr>
                    <th>Domain</th>
                    <th>Average Risk</th>
                    <th>Highest Risk</th>
                    <th>Scans</th>
                    <th>Reputation</th>
                    <th>Last Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {topThreats.map((threat) => {
                    const reputation = threat.reputation || "Unknown";
                    const classification = threat.classification || reputation;
                    return (
                      <tr key={threat.domain}>
                        <td className="threat-domain-cell">{threat.domain}</td>
                        <td>{threat.average_risk}%</td>
                        <td className="threat-risk-cell">{threat.highest_risk}%</td>
                        <td>{threat.scan_count || 1}</td>
                        <td>
                          <span className={`threat-chip ${riskBadgeClass(classification).replace("text-bg-", "")}`}>
                            {reputation}
                          </span>
                        </td>
                        <td title={formatDateTime(threat.last_seen)}>
                          {formatRelativeTime(threat.last_seen)}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>
        ) : null}

        {!searched && !isLoading && !record && topThreats.length === 0 ? (
          <EmptyState
            icon="bi-search-heart"
            title="Threat intelligence workspace"
            description="Enter a domain above to inspect its reputation profile, or load the live dataset of top threats tracked by ScamShield."
            actionLabel="Load Top Threats"
            onAction={loadTopThreats}
          />
        ) : null}
      </div>
    </PageContainer>
  );
}

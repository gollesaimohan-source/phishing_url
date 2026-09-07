import { formatDateTime } from "../utils/formatters.js";
import { formatRelativeTime } from "../utils/formatRelativeTime.js";

export default function ThreatIntelCard({ threatIntel, domainName }) {
  if (!threatIntel) return null;

  const domain = domainName || threatIntel.domain || "Unknown Domain";
  const isKnown = threatIntel.known_domain !== undefined ? threatIntel.known_domain : true;
  const scanCount = threatIntel.scan_count !== undefined 
    ? threatIntel.scan_count 
    : (threatIntel.previous_scans !== undefined ? threatIntel.previous_scans : 1);
  const avgRisk = threatIntel.average_risk !== undefined ? threatIntel.average_risk : 0;
  const maxRisk = threatIntel.highest_risk !== undefined ? threatIntel.highest_risk : 0;
  const reputation = threatIntel.reputation || "Unknown";
  const firstSeen = threatIntel.first_seen;
  const lastSeen = threatIntel.last_seen;
  const reasons = threatIntel.reasons || [];

  const getReputationBadge = (rep) => {
    const norm = rep.toLowerCase();
    if (norm.includes("bad")) return "text-bg-danger";
    if (norm.includes("suspicious")) return "text-bg-warning";
    if (norm.includes("unknown")) return "text-bg-secondary";
    return "text-bg-success";
  };

  return (
    <div className="threat-intel-card glass-panel animate-fade-in">
      <div className="threat-intel-header">
        <div className="d-flex align-items-center gap-2">
          <i className="bi bi-server" />
          <h3>Threat Database Record</h3>
        </div>
        <span className={`threat-intel-badge ${isKnown ? "warning" : "success"}`}>
          {isKnown ? "Known Threat" : "New Domain"}
        </span>
      </div>

      <div className="threat-intel-body">
        <div className="threat-intel-title-row">
          <span className="threat-intel-domain">{domain}</span>
          <span className={`threat-intel-reputation ${getReputationBadge(reputation)}`}>
            Reputation: {reputation}
          </span>
        </div>

        <div className="threat-intel-grid">
          <div className="threat-intel-metric">
            <span>Scan Count</span>
            <strong>{scanCount}</strong>
          </div>
          <div className="threat-intel-metric">
            <span>Average Risk</span>
            <strong>{avgRisk}%</strong>
          </div>
          <div className="threat-intel-metric danger">
            <span>Highest Risk</span>
            <strong>{maxRisk}%</strong>
          </div>
        </div>

        <div className="threat-intel-details">
          <div>
            <span>First Seen</span>
            <strong title={formatDateTime(firstSeen)}>{formatRelativeTime(firstSeen)}</strong>
          </div>
          <div>
            <span>Last Analyzed</span>
            <strong title={formatDateTime(lastSeen)}>{formatRelativeTime(lastSeen)}</strong>
          </div>
        </div>

        {reasons && reasons.length > 0 ? (
          <div className="threat-intel-tags-wrap">
            <h5>Aggregated Threat Indicators</h5>
            <div className="threat-intel-tags">
              {reasons.map((reason, idx) => (
                <span key={idx} className="threat-intel-tag">
                  {reason}
                </span>
              ))}
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}

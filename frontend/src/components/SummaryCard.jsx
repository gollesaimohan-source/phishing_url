export default function SummaryCard({ icon, title, value, description, variant = "info" }) {
  const accentMap = {
    info: { glow: "rgba(137, 206, 255, 0.18)", tint: "rgba(137, 206, 255, 0.12)", color: "var(--brand)" },
    danger: { glow: "rgba(255, 180, 171, 0.16)", tint: "rgba(255, 180, 171, 0.12)", color: "var(--danger)" },
    success: { glow: "rgba(134, 239, 172, 0.14)", tint: "rgba(134, 239, 172, 0.1)", color: "var(--success)" },
    warning: { glow: "rgba(255, 184, 110, 0.16)", tint: "rgba(255, 184, 110, 0.12)", color: "var(--warning)" },
  };

  const accent = accentMap[variant] || accentMap.info;

  return (
    <div className="summary-card glass-panel h-100 overflow-hidden">
      <div className="summary-card-glow" style={{ background: accent.glow }} />
      <div className="summary-card-accent" style={{ background: accent.color }} />

      <div className="summary-card-body">
        <div className="summary-card-header">
          <span>{title}</span>
          <div className="summary-card-icon" style={{ background: accent.tint, color: accent.color }}>
            <i className={`bi ${icon}`} />
          </div>
        </div>

        <div>
          <h3>{value}</h3>
          <p>{description}</p>
        </div>
      </div>
    </div>
  );
}

import PageContainer from "../layouts/PageContainer.jsx";
import { useTheme } from "../hooks/useTheme.js";

export default function Settings() {
  const { theme, toggleTheme } = useTheme();

  return (
    <PageContainer title="Settings" subtitle="ScamShield system parameters and operational metadata configurations.">
      <div className="settings-shell row justify-content-center animate-fade-in">
        <div className="col-12 col-md-8 col-lg-7">
          <div className="settings-card glass-panel overflow-hidden">
            <div className="settings-card-header">
              <i className="bi bi-sliders" />
              <h3>Engine Configuration</h3>
            </div>
            <div className="settings-card-body">
              <div className="settings-option-row">
                <div>
                  <h4>Theme Mode</h4>
                  <p>Choose the workspace appearance for this device.</p>
                </div>
                <button
                  className="theme-toggle settings-theme-toggle"
                  type="button"
                  onClick={toggleTheme}
                  aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
                >
                  <i className={`bi ${theme === "dark" ? "bi-sun" : "bi-moon-stars"}`} />
                  <span>{theme === "dark" ? "Light" : "Dark"}</span>
                </button>
              </div>

              <div className="settings-option-row">
                <div>
                  <h4>Scam Detection Aggregator</h4>
                  <p>Analyzers active: URL, Domain, SSL, Keywords, Reputation.</p>
                </div>
                <span className="settings-tag success">Active</span>
              </div>

              <div className="settings-option-row">
                <div>
                  <h4>API Base Endpoint</h4>
                  <p>Local server connection proxy configuration.</p>
                </div>
                <span className="settings-tag neutral mono">/api</span>
              </div>

              <div className="settings-option-row last">
                <div>
                  <h4>AI Explanation Provider</h4>
                  <p>Modular LLM text summary generator.</p>
                </div>
                <span className="settings-tag info">Mock LLM Provider</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </PageContainer>
  );
}

import PageContainer from "../layouts/PageContainer.jsx";
import { useAuth } from "../hooks/useAuth.js";
import { formatDateTime } from "../utils/formatters.js";
import { formatRelativeTime } from "../utils/formatRelativeTime.js";

export default function Profile() {
  const { user } = useAuth();

  return (
    <PageContainer title="Profile" subtitle="Current authenticated threat analyst credentials and session context.">
      <div className="profile-shell row justify-content-center animate-fade-in">
        <div className="col-12 col-md-8 col-lg-7">
          <div className="profile-card glass-panel overflow-hidden">
            <div className="profile-card-header">
              <i className="bi bi-person-badge" />
              <h3>Analyst Profile Details</h3>
            </div>
            <div className="profile-card-body">
              <div className="profile-identity-row">
                <div className="profile-avatar">
                  {(user?.username || user?.email || "A").charAt(0).toUpperCase()}
                </div>
                <div>
                  <h4>{user?.username || "Threat Analyst"}</h4>
                  <span className="profile-role-pill">{user?.role || "user"}</span>
                </div>
              </div>

              <div className="profile-details-grid">
                <div className="profile-detail-row">
                  <div className="profile-detail-label">Email Address</div>
                  <div className="profile-detail-value">{user?.email || "Not Available"}</div>
                </div>
                <div className="profile-detail-row">
                  <div className="profile-detail-label">User ID</div>
                  <div className="profile-detail-value mono">{user?.user_id || "Not Available"}</div>
                </div>
                <div className="profile-detail-row">
                  <div className="profile-detail-label">Role Authority</div>
                  <div className="profile-detail-value">{user?.role || "Standard User"}</div>
                </div>
                <div className="profile-detail-row last">
                  <div className="profile-detail-label">Last Login Session</div>
                  <div className="profile-detail-value" title={formatDateTime(user?.last_login)}>
                    {formatRelativeTime(user?.last_login)}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </PageContainer>
  );
}

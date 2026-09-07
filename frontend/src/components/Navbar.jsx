import { useState, useRef, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../hooks/useAuth.js";
import { useTheme } from "../hooks/useTheme.js";
import { formatDateTime } from "../utils/formatters.js";
import { useToast } from "../hooks/useToast.js";
import { formatRelativeTime } from "../utils/formatRelativeTime.js";

export default function Navbar({ onToggleSidebar }) {
  const { logout, user } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const navigate = useNavigate();
  const { showToast } = useToast();
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const dropdownRef = useRef(null);

  const handleLogout = async () => {
    setDropdownOpen(false);
    try {
      await logout();
    } catch (error) {
      console.error("Logout request failed", error);
    } finally {
      showToast("You have been logged out successfully.", "success");
      navigate("/login", { replace: true });
    }
  };

  useEffect(() => {
    function handleClickOutside(event) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setDropdownOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const getInitials = () => {
    const name = user?.username || user?.email || "A";
    return name.charAt(0).toUpperCase();
  };

  return (
    <header className="topbar d-flex align-items-center justify-content-between">
      <div className="d-flex align-items-center gap-3">
        <button
          className="btn btn-link text-white p-0 d-md-none border-0"
          type="button"
          onClick={onToggleSidebar}
          aria-label="Toggle Navigation"
        >
          <i className="bi bi-list fs-3" />
        </button>
        <Link to="/dashboard" className="topbar-brand d-flex align-items-center gap-2 text-decoration-none">
          <span className="brand-mark d-flex align-items-center justify-content-center rounded-3 fs-5">S</span>
          <span className="text-light fw-bold h5 mb-0 d-none d-sm-inline-block tracking-tight">ScamShield</span>
        </Link>
      </div>

      <div className="d-flex align-items-center gap-3">
        <button
          className="theme-toggle"
          type="button"
          onClick={toggleTheme}
          aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
        >
          <i className={`bi ${theme === "dark" ? "bi-sun" : "bi-moon-stars"}`} />
          <span>{theme === "dark" ? "Light" : "Dark"}</span>
        </button>
        <div className="position-relative" ref={dropdownRef}>
          <button
            className="user-menu-button"
            onClick={() => setDropdownOpen(!dropdownOpen)}
            aria-expanded={dropdownOpen}
            type="button"
          >
            <div className="user-avatar">{getInitials()}</div>
          </button>

          {dropdownOpen ? (
            <div className="user-menu-popover position-absolute end-0 mt-2" style={{ width: "260px", zIndex: 1100 }}>
              <div className="pb-3 border-bottom border-secondary border-opacity-15">
                <h6 className="mb-0 text-light fw-bold">{user?.username || "Analyst"}</h6>
                <span className="text-muted small d-block text-truncate">{user?.email}</span>
                <span className="badge bg-secondary-subtle text-secondary-emphasis mt-1.5 fs-8 text-uppercase tracking-wider px-2">{user?.role || "User"}</span>
              </div>
              <div className="py-2 d-flex flex-column gap-1 border-bottom border-secondary border-opacity-15">
                <Link to="/profile" className="d-flex align-items-center gap-2 text-decoration-none py-2 px-2 rounded-2 dropdown-item-hover small" onClick={() => setDropdownOpen(false)}>
                  <i className="bi bi-person" /> Profile Account
                </Link>
                <Link to="/settings" className="d-flex align-items-center gap-2 text-decoration-none py-2 px-2 rounded-2 dropdown-item-hover small" onClick={() => setDropdownOpen(false)}>
                  <i className="bi bi-gear" /> Preferences & Settings
                </Link>
              </div>
              <div className="pt-2">
                <div className="text-muted fs-8 mb-2">
                  Last login: <br />
                  <strong className="text-light" title={formatDateTime(user?.last_login)}>
                    {formatRelativeTime(user?.last_login)}
                  </strong>
                </div>
                <button
                  className="btn btn-danger btn-sm w-100 rounded-3 d-flex align-items-center justify-content-center gap-2"
                  type="button"
                  onClick={handleLogout}
                >
                  <i className="bi bi-box-arrow-right" />
                  Logout
                </button>
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </header>
  );
}

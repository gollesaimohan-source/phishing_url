import { useEffect, useState } from "react";
import PageContainer from "../layouts/PageContainer.jsx";
import EmptyState from "../components/EmptyState.jsx";
import SkeletonCard from "../components/SkeletonCard.jsx";
import ErrorAlert from "../components/ErrorAlert.jsx";
import { useToast } from "../hooks/useToast.js";
import StatusBadge from "../components/StatusBadge.jsx";
import {
  deleteLocalHistory,
  deleteScan,
  getLocalHistory,
  getScanHistory,
} from "../services/scanService.js";
import { formatDateTime } from "../utils/formatters.js";
import { formatRelativeTime } from "../utils/formatRelativeTime.js";

const CLASSIFICATION_OPTIONS = [
  "",
  "Safe",
  "Suspicious",
  "Malicious",
  "Low",
  "Medium",
  "High",
  "Unknown",
];
const PAGE_SIZE = 10;

export default function History() {
  const [items, setItems] = useState([]);
  const [pagination, setPagination] = useState({
    page: 1,
    per_page: PAGE_SIZE,
    total: 0,
    total_pages: 0,
    has_next: false,
    has_prev: false,
  });
  const [searchInput, setSearchInput] = useState("");
  const [search, setSearch] = useState("");
  const [classification, setClassification] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState("");
  const [deletingId, setDeletingId] = useState("");
  const [deleteCandidate, setDeleteCandidate] = useState("");
  const { showToast } = useToast();

  useEffect(() => {
    loadHistory({ page: pagination.page, search, classification });
  }, [pagination.page, search, classification]);

  async function loadHistory({ page, search: searchTerm, classification: filter }) {
    setIsLoading(true);
    setError("");

    try {
      const response = await getScanHistory({
        page,
        perPage: PAGE_SIZE,
        search: searchTerm,
        classification: filter,
      });
      const payload = response.data || {};
      let itemsFromServer = payload.items || [];
      let paginationFromServer = payload.pagination || pagination;

      // If server returned no results (e.g., no backend history or offline),
      // fall back to local anonymous history stored in the browser.
      if (!itemsFromServer || itemsFromServer.length === 0) {
        const local = getLocalHistory({ page, perPage: PAGE_SIZE });
        itemsFromServer = local.items || [];
        paginationFromServer = local.pagination || paginationFromServer;
      }

      setItems(itemsFromServer);
      setPagination(paginationFromServer);
    } catch (requestError) {
      // On error, try to show local anonymous history so the page is usable.
      const local = getLocalHistory({ page, perPage: PAGE_SIZE });
      setItems(local.items || []);
      setPagination(local.pagination || pagination);
      setError("");
    } finally {
      setIsLoading(false);
    }
  }

  function submitSearch(event) {
    event.preventDefault();
    setSearch(searchInput.trim());
    setPagination((current) => ({ ...current, page: 1 }));
  }

  function updateClassification(event) {
    setClassification(event.target.value);
    setPagination((current) => ({ ...current, page: 1 }));
  }

  // Manual-only verification: no frontend test suite currently covers local vs backend deletion.
  async function handleDelete(scanId) {
    if (!scanId) return;

    setDeletingId(scanId);
    setError("");

    try {
      if (scanId.startsWith("local-")) {
        deleteLocalHistory(scanId);
      } else {
        await deleteScan(scanId);
      }
      const nextPage =
        items.length === 1 && pagination.page > 1 ? pagination.page - 1 : pagination.page;
      setPagination((current) => ({ ...current, page: nextPage }));
      await loadHistory({ page: nextPage, search, classification });
      showToast("History entry deleted successfully.", "success");
    } catch (requestError) {
      const message = requestError.message || "Failed to delete scan history entry.";
      setError(message);
      showToast(message, "error");
    } finally {
      setDeletingId("");
    }
  }

  function goToPage(page) {
    setPagination((current) => ({ ...current, page }));
  }

  const hasActiveFilters = Boolean(search || classification);
  const suspiciousCount = items.filter((scan) => (scan.classification || "").toLowerCase() === "suspicious").length;
  const maliciousCount = items.filter((scan) => (scan.classification || "").toLowerCase() === "malicious").length;

  return (
    <PageContainer title="History & Analytics" subtitle="Review prior detections, filter outcomes, and track your security investigations over time.">
      {error ? <ErrorAlert message={error} onDismiss={() => setError("")} /> : null}

      <div className="history-shell">
        <section className="history-stats">
          <div className="history-stat-card glass-panel">
            <span className="history-stat-label">Total Scans</span>
            <strong>{formatCount(pagination.total)}</strong>
            <small>Recorded investigations</small>
          </div>
          <div className="history-stat-card glass-panel">
            <span className="history-stat-label">Suspicious</span>
            <strong>{formatCount(suspiciousCount)}</strong>
            <small>Awaiting review</small>
          </div>
          <div className="history-stat-card glass-panel">
            <span className="history-stat-label">Malicious</span>
            <strong>{formatCount(maliciousCount)}</strong>
            <small>High confidence findings</small>
          </div>
        </section>

        <section className="glass-panel history-toolbar">
          <form className="history-toolbar-form" onSubmit={submitSearch}>
            <div className="history-field">
              <label htmlFor="history-search">Search scans</label>
              <div className="history-input-group">
                <span>
                  <i className="bi bi-search" />
                </span>
                <input
                  id="history-search"
                  value={searchInput}
                  onChange={(event) => setSearchInput(event.target.value)}
                  placeholder="Search by URL or classification..."
                />
              </div>
            </div>
            <div className="history-field history-field-small">
              <label htmlFor="history-filter">Classification</label>
              <select id="history-filter" value={classification} onChange={updateClassification}>
                {CLASSIFICATION_OPTIONS.map((option) => (
                  <option key={option || "all"} value={option}>
                    {option || "All classifications"}
                  </option>
                ))}
              </select>
            </div>
            <button className="btn-premium-primary history-action-button" type="submit" disabled={isLoading}>
              <i className="bi bi-funnel" />
              Filter
            </button>
          </form>
        </section>

        <section className="glass-panel history-table-card">
          <div className="history-table-header">
            <div>
              <span className="section-kicker">Audit trail</span>
              <h3>Historical detections</h3>
            </div>
            <span className="section-badge">{formatCount(pagination.total)} results</span>
          </div>

          {isLoading ? <SkeletonCard className="skeleton-history" rows={6} /> : null}

          {!isLoading && items.length > 0 ? (
            <>
              <div className="table-responsive">
                <table className="history-table">
                  <thead>
                    <tr>
                      <th>URL</th>
                      <th>Risk Score</th>
                      <th>Classification</th>
                      <th>Scan Date</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((scan) => (
                      <tr key={scan.scan_id}>
                        <td className="history-url-cell" title={scan.url}>
                          {scan.url || "Unknown URL"}
                        </td>
                        <td>
                          <span className={`history-score ${scoreClass(scan.risk_score)}`}>
                            {Number(scan.risk_score || 0)}%
                          </span>
                        </td>
                        <td>
                          <StatusBadge status={scan.classification || "Unknown"} />
                        </td>
                        <td title={formatDateTime(scan.scan_date)}>
                          {formatRelativeTime(scan.scan_date)}
                        </td>
                        <td>
                          <button
                            className="history-delete-button"
                            type="button"
                            onClick={() => setDeleteCandidate(scan.scan_id)}
                            disabled={deletingId === scan.scan_id}
                          >
                            {deletingId === scan.scan_id ? "Deleting..." : "Delete"}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <HistoryPagination pagination={pagination} onPageChange={goToPage} />
            </>
          ) : null}

          {!isLoading && items.length === 0 ? (
            <EmptyState
              icon={hasActiveFilters ? "bi-funnel" : "bi-clock-history"}
              title={hasActiveFilters ? "No Matching Scans" : "No Scan History Yet"}
              description={
                hasActiveFilters
                  ? "Adjust the search term or classification filter to find relevant scan records."
                  : "Run a URL scan to populate the production history timeline."
              }
            />
          ) : null}
        </section>
      </div>

      {deleteCandidate ? (
        <div className="modal fade show d-block" role="dialog" aria-modal="true" aria-labelledby="delete-scan-title">
          <div className="modal-dialog modal-dialog-centered">
            <div className="modal-content scamshield-confirm-modal">
              <div className="modal-header">
                <h5 className="modal-title" id="delete-scan-title">Delete scan record?</h5>
                <button
                  type="button"
                  className="btn-close"
                  aria-label="Close"
                  onClick={() => setDeleteCandidate("")}
                />
              </div>
              <div className="modal-body">Delete this scan record? This cannot be undone.</div>
              <div className="modal-footer">
                <button className="btn-premium-secondary" type="button" onClick={() => setDeleteCandidate("")}>
                  Cancel
                </button>
                <button
                  className="btn btn-danger"
                  type="button"
                  onClick={() => {
                    const scanId = deleteCandidate;
                    setDeleteCandidate("");
                    handleDelete(scanId);
                  }}
                >
                  Delete
                </button>
              </div>
            </div>
          </div>
        </div>
      ) : null}
      {deleteCandidate ? <div className="modal-backdrop fade show" onClick={() => setDeleteCandidate("")} /> : null}
    </PageContainer>
  );
}

function HistoryPagination({ pagination, onPageChange }) {
  if (!pagination.total_pages || pagination.total_pages <= 1) {
    return null;
  }

  const pages = pageWindow(pagination.page, pagination.total_pages);

  return (
    <div className="history-pagination">
      <div className="text-muted small">
        Page {pagination.page} of {pagination.total_pages}
      </div>
      <nav aria-label="Scan history pages">
        <ul className="pagination pagination-sm mb-0">
          <li className={`page-item ${pagination.has_prev ? "" : "disabled"}`}>
            <button
              className="page-link"
              type="button"
              onClick={() => onPageChange(pagination.page - 1)}
              disabled={!pagination.has_prev}
            >
              Previous
            </button>
          </li>
          {pages.map((page) => (
            <li key={page} className={`page-item ${page === pagination.page ? "active" : ""}`}>
              <button className="page-link" type="button" onClick={() => onPageChange(page)}>
                {page}
              </button>
            </li>
          ))}
          <li className={`page-item ${pagination.has_next ? "" : "disabled"}`}>
            <button
              className="page-link"
              type="button"
              onClick={() => onPageChange(pagination.page + 1)}
              disabled={!pagination.has_next}
            >
              Next
            </button>
          </li>
        </ul>
      </nav>
    </div>
  );
}

function pageWindow(current, total) {
  const start = Math.max(1, current - 2);
  const end = Math.min(total, start + 4);
  return Array.from({ length: end - start + 1 }, (_, index) => start + index);
}

function formatCount(value) {
  return new Intl.NumberFormat().format(Number(value || 0));
}

function scoreClass(score) {
  const value = Number(score || 0);
  if (value >= 70) return "history-score-danger";
  if (value >= 40) return "history-score-warning";
  return "history-score-success";
}

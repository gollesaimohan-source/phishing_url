import { createContext, useCallback, useMemo, useState } from "react";

export const ToastContext = createContext(null);

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);

  const showToast = useCallback((message, type = "info") => {
    const id = `${Date.now()}-${Math.random()}`;
    setToasts((current) => [...current, { id, message, type }]);
    window.setTimeout(() => {
      setToasts((current) => current.filter((toast) => toast.id !== id));
    }, 4000);
  }, []);

  const dismissToast = useCallback((id) => {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  const value = useMemo(() => ({ showToast }), [showToast]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="toast-container position-fixed bottom-0 end-0 p-3" aria-live="polite" aria-atomic="true">
        {toasts.map((toast) => (
          <div key={toast.id} className={`toast show scamshield-toast scamshield-toast-${toast.type}`} role="status">
            <div className="toast-header">
              <i className={`bi ${toast.type === "success" ? "bi-check-circle" : toast.type === "error" ? "bi-exclamation-triangle" : "bi-info-circle"} me-2`} />
              <strong className="me-auto">ScamShield</strong>
              <button
                type="button"
                className="btn-close"
                aria-label="Close notification"
                onClick={() => dismissToast(toast.id)}
              />
            </div>
            <div className="toast-body">{toast.message}</div>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

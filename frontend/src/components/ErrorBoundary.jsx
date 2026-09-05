import React from "react";

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError() {
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    console.error("frontend_render_error", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <main
          role="alert"
          style={{
            alignItems: "center",
            display: "flex",
            justifyContent: "center",
            minHeight: "100vh",
            padding: "2rem",
            textAlign: "center",
          }}
        >
          <div>
            <h1>Something went wrong</h1>
            <p>Please refresh the page and try again.</p>
            <button type="button" onClick={() => window.location.reload()}>
              Refresh page
            </button>
          </div>
        </main>
      );
    }

    return this.props.children;
  }
}

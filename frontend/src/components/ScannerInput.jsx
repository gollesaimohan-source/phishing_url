import { useEffect, useState } from "react";

export default function ScannerInput({
  activeType,
  value,
  onChange,
  onFileChange,
  selectedFile,
  isScanning,
  onLoadSample,
  onSubmit,
  onReset,
  onClearFile,
}) {
  const [previewUrl, setPreviewUrl] = useState("");
  const [previewError, setPreviewError] = useState(false);

  useEffect(() => {
    if (!selectedFile) {
      setPreviewUrl("");
      setPreviewError(false);
      return undefined;
    }

    let objectUrl = "";
    try {
      objectUrl = URL.createObjectURL(selectedFile);
      setPreviewUrl(objectUrl);
      setPreviewError(false);
    } catch {
      setPreviewUrl("");
      setPreviewError(true);
    }

    return () => {
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [selectedFile]);

  function handleFileChange(eventOrFile) {
    const file = eventOrFile?.target ? eventOrFile.target.files?.[0] : eventOrFile;
    if (file) {
      onFileChange({ target: { files: [file] } });
    }

    function clearSelectedFile(event) {
      event.preventDefault();
      event.stopPropagation();
      onClearFile();
    }
  }

  return (
    <div className="scanner-input-panel glass-panel">
      <div className="scanner-panel-heading">
        <div>
          <span className="scanner-eyebrow">Selected module</span>
          <h2>{activeType.label} Analysis</h2>
        </div>
        {(() => {
          const status = activeType.status ? activeType.status : activeType.comingSoon ? "coming" : "available";
          const label = status === "available" ? "Available" : status === "beta" ? "Beta" : "Coming Soon";
          return <span className={`feature-status ${status}`}>{label}</span>;
        })()}
      </div>

      <form onSubmit={onSubmit}>
        {activeType.id === "url" ? (
          <div className="scanner-field">
            <label htmlFor="scanner-url">{activeType.inputLabel}</label>
            <div className="scanner-url-input">
              <i className="bi bi-link-45deg" />
              <input
                id="scanner-url"
                type="text"
                value={value}
                onChange={(event) => onChange(event.target.value)}
                placeholder={activeType.placeholder}
                disabled={isScanning}
              />
            </div>
          </div>
        ) : null}

        {['email', 'sms', 'news'].includes(activeType.id) ? (
          <div className="scanner-field">
            <label htmlFor="scanner-text">{activeType.inputLabel}</label>
            <textarea
              id="scanner-text"
              value={value}
              onChange={(event) => onChange(event.target.value)}
              placeholder={activeType.placeholder}
              rows={8}
              disabled={isScanning}
            />
          </div>
        ) : null}

        {['image', 'video'].includes(activeType.id) ? (
          <div className="scanner-field">
            <label>{activeType.inputLabel}</label>
            <label
              className="scanner-dropzone"
              htmlFor="scanner-file"
              onDragOver={(event) => event.preventDefault()}
              onDrop={(event) => {
                event.preventDefault();
                handleFileChange(event.dataTransfer.files?.[0]);
              }}
            >
              <input
                id="scanner-file"
                type="file"
                accept={activeType.id === 'image' ? 'image/*' : 'video/*'}
                onChange={handleFileChange}
                disabled={isScanning}
              />
              {selectedFile && previewUrl && !previewError ? (
                <div className="scanner-preview" onClick={(event) => event.preventDefault()}>
                  {activeType.id === "image" ? (
                    <img
                      src={previewUrl}
                      alt={`Preview of ${selectedFile.name}`}
                      onError={() => setPreviewError(true)}
                    />
                  ) : (
                    <video
                      src={previewUrl}
                      muted
                      controls
                      preload="metadata"
                      onError={() => setPreviewError(true)}
                    />
                  )}
                  <button
                    className="scanner-preview-remove"
                    type="button"
                    aria-label="Remove selected file"
                    onClick={clearSelectedFile}
                  >
                    <i className="bi bi-x-lg" aria-hidden="true" />
                  </button>
                  <span className="scanner-preview-caption">{selectedFile.name}</span>
                </div>
              ) : (
                <>
                  <i className={`bi ${activeType.id === 'image' ? 'bi-cloud-upload' : 'bi-film'}`} />
                  <strong>
                    {selectedFile?.name || `Choose a ${activeType.label.toLowerCase()} file to upload`}
                  </strong>
                  <span>
                    {selectedFile
                      ? `Ready to scan ${selectedFile.name}`
                      : `Upload a ${activeType.label.toLowerCase()} and ScamShield will analyze it.`}
                  </span>
                </>
              )}
            </label>
          </div>
        ) : null}

        {!activeType.comingSoon && !["image", "video"].includes(activeType.id) ? (
          <button className="scanner-sample-button" type="button" onClick={onLoadSample}>
            <i className="bi bi-magic" />
            Use sample
          </button>
        ) : null}

        <div className="scanner-actions">
          <button className="btn-premium-primary" type="submit" disabled={isScanning || activeType.comingSoon}>
            {isScanning ? (
              <>
                <span className="spinner-border spinner-border-sm" aria-hidden="true" />
                Analyzing
              </>
            ) : (
              <>
                Run AI Scan
                <i className="bi bi-arrow-right" />
              </>
            )}
          </button>
          <button className="btn-premium-secondary" type="button" onClick={onReset}>
            Reset
          </button>
        </div>
      </form>
    </div>
  );
}

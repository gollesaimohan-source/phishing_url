import { useMemo, useState, useEffect } from "react";
import PageContainer from "../layouts/PageContainer.jsx";
import ScannerHero from "../components/ScannerHero.jsx";
import DetectionSelector from "../components/DetectionSelector.jsx";
import ScannerInput from "../components/ScannerInput.jsx";
import ScannerResult from "../components/ScannerResult.jsx";
import LoadingState from "../components/LoadingState.jsx";
import ErrorAlert from "../components/ErrorAlert.jsx";
import EmptyState from "../components/EmptyState.jsx";
import {
  analyzeContent,
  analyzeMedia,
  scanUrl,
  scanUrlAuthenticated,
} from "../services/scanService.js";
import { getStoredToken } from "../services/apiClient.js";

const SCAN_TYPES = [
  {
    id: "url",
    label: "URL",
    icon: "bi-globe2",
    description: "Phishing links, spoofed domains, redirects",
    inputLabel: "URL or Domain",
    placeholder: "https://example-login-check.com",
  },
  {
    id: "email",
    label: "Email",
    icon: "bi-envelope-at",
    description: "Phishing emails and impersonation attempts",
    inputLabel: "Email Content",
    placeholder: "Paste the full suspicious email here...",
  },
  {
    id: "sms",
    label: "SMS",
    icon: "bi-chat-left-text",
    description: "Payment scams, OTP traps, urgent messages",
    inputLabel: "SMS or Message Content",
    placeholder: "Paste the suspicious SMS or chat message here...",
  },
  {
    id: "news",
    label: "Fake News",
    icon: "bi-newspaper",
    description: "Viral claims, social posts, news snippets",
    inputLabel: "News Article or Post",
    placeholder: "Paste the suspicious news article or social post here...",
  },
  {
    id: "image",
    label: "AI Image",
    icon: "bi-image",
    description: "Generated images and manipulated visuals",
    inputLabel: "Upload an image file",
    placeholder: "",
  },
  {
    id: "video",
    label: "Deepfake Video",
    icon: "bi-camera-video",
    description: "Synthetic video and manipulated media",
    inputLabel: "Upload a video file",
    placeholder: "",
  },
];

const SAMPLE_INPUTS = {
  url: "https://hdfc-netbanking-verify.secure-update.xyz/login",
  email:
    "Dear customer, your account has been suspended. Verify your KYC and enter your UPI PIN immediately at http://bank-verify-secure.example to avoid account closure.",
  sms:
    "URGENT: Your package is held by customs. Pay Rs 49 now and verify OTP at delivery-update.example or it will be returned.",
  news:
    "Breaking: Government announces instant refunds for all citizens today only. Submit Aadhaar, bank details and PIN through this short link to claim.",
};

export default function Scanner() {
  const [activeTypeId, setActiveTypeId] = useState("url");
  const [inputs, setInputs] = useState({
    url: "",
    email: "",
    sms: "",
    news: "",
  });
  const [selectedFile, setSelectedFile] = useState(null);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [isScanning, setIsScanning] = useState(false);

  const activeType = useMemo(
    () => SCAN_TYPES.find((type) => type.id === activeTypeId) || SCAN_TYPES[0],
    [activeTypeId],
  );

  function selectType(typeId) {
    setActiveTypeId(typeId);
    setResult(null);
    setError("");
    setSelectedFile(null);
    // Smooth-scroll to the input area for the newly selected type
    try {
      const el = document.querySelector(".scanner-input-panel");
      if (el && el.scrollIntoView) el.scrollIntoView({ behavior: "smooth", block: "center" });
      const inputEl = document.getElementById(typeId === "url" ? "scanner-url" : "scanner-file");
      if (inputEl && inputEl.focus) inputEl.focus({ preventScroll: true });
    } catch (e) {}
  }

  useEffect(() => {
    if (result) {
      try {
        const el = document.querySelector(".scanner-result");
        if (el && el.scrollIntoView) el.scrollIntoView({ behavior: "smooth", block: "start" });
      } catch (e) {}
    }
  }, [result]);

  function updateInput(value) {
    setInputs((current) => ({ ...current, [activeTypeId]: value }));
  }

  function loadSample() {
    const sample = SAMPLE_INPUTS[activeTypeId];
    if (sample) {
      updateInput(sample);
      setResult(null);
      setError("");
    }
  }

  function handleFileChange(event) {
    const file = event.target.files?.[0];
    if (file) {
      setSelectedFile(file);
    }
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");
    setResult(null);

    if (activeTypeId === "image" || activeTypeId === "video") {
      if (!selectedFile) {
        setError(`Please upload a ${activeType.label.toLowerCase()} before scanning.`);
        return;
      }
    } else {
      const value = inputs[activeTypeId]?.trim();
      if (!value) {
        setError(`Please enter ${activeType.inputLabel.toLowerCase()} to analyze.`);
        return;
      }
    }

    setIsScanning(true);
    try {
      if (activeTypeId === "url") {
        const response = await (getStoredToken()
          ? scanUrlAuthenticated(inputs.url.trim())
          : scanUrl(inputs.url.trim()));
        setResult(normalizeUrlResult(response, inputs.url.trim()));
      } else if (activeTypeId === "image" || activeTypeId === "video") {
        const metadata = await loadMediaMetadata(selectedFile);
        const response = await analyzeMedia(selectedFile, metadata);
        setResult(normalizeMediaResult(response, selectedFile));
      } else {
        const response = await analyzeContent(
          inputs[activeTypeId].trim(),
          contentTypeFor(activeTypeId),
        );
        setResult(normalizeTextResult(response, inputs[activeTypeId].trim(), activeTypeId));
      }
    } catch (requestError) {
      setError(requestError.message || "Scan failed. Please try again.");
    } finally {
      setIsScanning(false);
    }
  }

  function resetScanner() {
    setInputs((current) => ({ ...current, [activeTypeId]: "" }));
    setSelectedFile(null);
    setResult(null);
    setError("");
  }

  async function loadMediaMetadata(file) {
    if (!file) return {};

    return new Promise((resolve) => {
      const metadata = {};
      if (file.type.startsWith("image/")) {
        const image = new Image();
        image.onload = () => {
          resolve({ width: image.naturalWidth, height: image.naturalHeight });
          URL.revokeObjectURL(image.src);
        };
        image.onerror = () => resolve({});
        image.src = URL.createObjectURL(file);
        return;
      }

      if (file.type.startsWith("video/")) {
        const video = document.createElement("video");
        video.preload = "metadata";
        video.onloadedmetadata = () => {
          resolve({
            width: video.videoWidth,
            height: video.videoHeight,
            duration: Math.round(video.duration),
          });
          URL.revokeObjectURL(video.src);
        };
        video.onerror = () => resolve({});
        video.src = URL.createObjectURL(file);
        return;
      }

      resolve({});
    });
  }

  return (
    <PageContainer
      title="AI Security Scanner"
      subtitle="Analyze URLs, Emails, SMS messages, News Articles, Images, and Videos using AI."
    >
      <div className="scanner-shell">
        <ScannerHero />

        <DetectionSelector types={SCAN_TYPES} activeTypeId={activeTypeId} onSelect={selectType} />

        <section className="scanner-workspace">
          <ScannerInput
            activeType={activeType}
            value={activeTypeId === "url" ? inputs.url : inputs[activeTypeId] || ""}
            onChange={updateInput}
            onFileChange={handleFileChange}
            selectedFile={selectedFile}
            onClearFile={() => setSelectedFile(null)}
            isScanning={isScanning}
            onLoadSample={loadSample}
            onSubmit={handleSubmit}
            onReset={resetScanner}
          />

          <aside className="scanner-context-panel glass-panel">
            <span className="scanner-eyebrow">Detection profile</span>
            <h3>{activeType.label}</h3>
            <p>{activeType.description}</p>
            <div className="context-list">
              <span>
                <i className="bi bi-check-circle" />
                Explainable classification
              </span>
              <span>
                <i className="bi bi-check-circle" />
                Risk scoring
              </span>
              <span>
                <i className="bi bi-check-circle" />
                Actionable recommendations
              </span>
            </div>
          </aside>
        </section>

        {error ? <ErrorAlert message={error} onDismiss={() => setError("")} /> : null}

        {isScanning ? <LoadingState message="Analyzing threat indicators and preparing explainable report..." /> : null}

        {!result && !isScanning && !error ? (
          <EmptyState
            icon="bi-shield-lock"
            title="Scanner Ready"
            description="Choose a scan type, submit suspicious content, and ScamShield will return a risk report."
          />
        ) : null}

        <ScannerResult result={result} />
      </div>
    </PageContainer>
  );
}

function contentTypeFor(typeId) {
  if (typeId === "email") return "email";
  if (typeId === "sms") return "sms";
  if (typeId === "news") return "news";
  return "message";
}

function normalizeMediaResult(response, file) {
  return {
    input: file?.name || "Uploaded media",
    risk_score: response.ai_likelihood ?? response.authenticity_score ?? 0,
    classification: response.risk_level || response.result || "Unknown",
    confidence: response.confidence,
    summary: response.explanation || response.simple_result || response.summary || "The media scan completed.",
    reasons: response.indicators?.map(indicatorText) || response.reasons || [],
    recommendations: [response.recommended_action].filter(Boolean),
    threat_intelligence: response.threat_intelligence,
    media_type: response.media_type,
    file_details: response.file,
    forensic_metrics: response.forensic_metrics,
    duration_seconds: response.duration_seconds,
  };
}

function normalizeUrlResult(response, input) {
  return {
    input,
    risk_score: response.risk_score ?? response.scam_probability ?? 0,
    classification: response.classification || response.risk_level || response.result || "Unknown",
    confidence: response.confidence,
    summary:
      response.explanation ||
      response.summary ||
      response.recommended_action ||
      "The URL scan completed, but no detailed AI summary was returned.",
    reasons: response.reasons || response.danger_indicators || response.indicators?.map(indicatorText) || [],
    recommendations: [response.recommended_action].filter(Boolean),
    threat_intelligence: response.threat_intelligence,
    domain: response.domain,
  };
}

function normalizeTextResult(response, input, typeId) {
  return {
    input: input.length > 140 ? `${input.slice(0, 140)}...` : input,
    risk_score: response.scam_probability ?? response.risk_score ?? 0,
    classification: response.risk_level || response.classification || "Unknown",
    confidence: response.confidence,
    summary:
      response.summary ||
      response.explanation ||
      `${SCAN_TYPES.find((type) => type.id === typeId)?.label || "Content"} analysis completed.`,
    reasons: response.indicators?.map(indicatorText) || response.reasons || [],
    recommendations: [response.recommended_action].filter(Boolean),
    threat_intelligence: response.threat_intelligence,
  };
}

function indicatorText(indicator) {
  if (typeof indicator === "string") return indicator;
  return [indicator.name, indicator.detail].filter(Boolean).join(": ");
}

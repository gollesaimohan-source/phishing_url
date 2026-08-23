from io import BytesIO
from unittest.mock import Mock, patch

import requests
from PIL import Image

from scamshield.ai.detector import analyze_media_file
from scamshield.services.image_forensics_service import ImageForensicsService


def _image_bytes():
    image = Image.new("RGB", (32, 32), (120, 80, 40))
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def _result(ai_probability=None, deepfake_probability=None, checked=True):
    return {
        "checked": checked,
        "ai_generated_probability": ai_probability,
        "deepfake_probability": deepfake_probability,
        "error": None if checked else "request timeout",
    }


def test_analyze_image_skips_http_without_credentials(monkeypatch):
    monkeypatch.delenv("SIGHTENGINE_API_USER", raising=False)
    monkeypatch.delenv("SIGHTENGINE_API_SECRET", raising=False)

    with patch("scamshield.services.image_forensics_service.requests.post") as post:
        result = ImageForensicsService().analyze_image(b"bytes", "sample.png")

    assert result == {
        "checked": False,
        "ai_generated_probability": None,
        "deepfake_probability": None,
        "error": "not_configured",
    }
    post.assert_not_called()


def test_analyze_image_parses_sightengine_payload(monkeypatch):
    monkeypatch.setenv("SIGHTENGINE_API_USER", "test-user")
    monkeypatch.setenv("SIGHTENGINE_API_SECRET", "test-secret")
    response = Mock()
    response.json.return_value = {
        "status": "success",
        "type": {"ai_generated": 0.92, "deepfake": 0.08},
    }

    with patch(
        "scamshield.services.image_forensics_service.requests.post",
        return_value=response,
    ) as post:
        result = ImageForensicsService().analyze_image(b"bytes", "sample.png")

    assert result == {
        "checked": True,
        "ai_generated_probability": 0.92,
        "deepfake_probability": 0.08,
        "error": None,
    }
    post.assert_called_once()
    assert post.call_args.kwargs["params"]["models"] == "genai,deepfake"
    assert post.call_args.kwargs["files"]["media"][0] == "sample.png"
    assert post.call_args.kwargs["timeout"] == 8


def test_analyze_image_handles_request_failure(monkeypatch):
    monkeypatch.setenv("SIGHTENGINE_API_USER", "test-user")
    monkeypatch.setenv("SIGHTENGINE_API_SECRET", "test-secret")

    with patch(
        "scamshield.services.image_forensics_service.requests.post",
        side_effect=requests.Timeout("timed out"),
    ):
        result = ImageForensicsService().analyze_image(b"bytes", "sample.png")

    assert result["checked"] is False
    assert result["error"] == "timed out"
    assert result["ai_generated_probability"] is None


def test_high_ai_probability_overrides_forensic_score(client):
    with patch(
        "scamshield.ai.detector.ImageForensicsService.analyze_image",
        return_value=_result(ai_probability=0.92),
    ):
        response = client.post(
            "/api/analyze-media",
            content_type="multipart/form-data",
            data={"file": (BytesIO(_image_bytes()), "photo.jpg")},
        )

    body = response.get_json()
    assert body["ai_likelihood"] >= 80
    assert body["risk_level"] == "May be AI-made"
    assert any("ML classifier" in item["name"] for item in body["indicators"])
    assert body["ml_classifier"]["ai_generated_probability"] == 0.92


def test_low_ai_probability_reduces_suspicious_forensic_score():
    file_bytes = _image_bytes()
    with patch(
        "scamshield.ai.detector.ImageForensicsService.analyze_image",
        return_value=_result(checked=False),
    ):
        forensic_only = analyze_media_file(
            "suspicious.png", "image/png", len(file_bytes), file_bytes=file_bytes
        )

    with patch(
        "scamshield.ai.detector.ImageForensicsService.analyze_image",
        return_value=_result(ai_probability=0.05),
    ):
        blended = analyze_media_file(
            "suspicious.png", "image/png", len(file_bytes), file_bytes=file_bytes
        )

    assert blended["ai_likelihood"] < forensic_only["ai_likelihood"]
    assert any("ML classifier" in item["name"] for item in blended["indicators"])


def test_failed_ml_check_keeps_forensic_only_result():
    file_bytes = _image_bytes()
    with patch(
        "scamshield.ai.detector.ImageForensicsService.analyze_image",
        return_value=_result(checked=False),
    ):
        result = analyze_media_file(
            "photo.jpg", "image/jpeg", len(file_bytes), file_bytes=file_bytes
        )

    assert result["ml_classifier"] is None
    assert not any("ML classifier" in item["name"] for item in result["indicators"])


def test_video_does_not_call_sightengine():
    with patch("scamshield.ai.detector.ImageForensicsService.analyze_image") as analyze:
        result = analyze_media_file("clip.mp4", "video/mp4", 200_000, duration=10)

    analyze.assert_not_called()
    assert result["ml_classifier"] is None
    assert any(item["name"] == "Frame-level model recommended" for item in result["indicators"])

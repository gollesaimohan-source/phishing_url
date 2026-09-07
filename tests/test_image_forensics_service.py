from io import BytesIO
import os
import tempfile
from unittest.mock import Mock, patch

import cv2
import numpy as np
import requests
from PIL import Image

from scamshield.ai.detector import (
    VIDEO_MAX_DURATION_SECONDS,
    analyze_media_file,
)
from scamshield.services.image_forensics_service import ImageForensicsService


def _image_bytes():
    image = Image.new("RGB", (32, 32), (120, 80, 40))
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def _normal_photo_bytes(with_exif=False):
    image = Image.new("RGB", (800, 600))
    pixels = image.load()
    for y in range(600):
        for x in range(800):
            pixels[x, y] = (
                int(70 + 120 * x / 800),
                int(90 + 100 * y / 600),
                int(130 + 50 * (x + y) / 1400),
            )
    output = BytesIO()
    if with_exif:
        exif = Image.Exif()
        exif[271] = "Example Camera"
        exif[272] = "Example Model"
        exif[36867] = "2026:08:23 12:00:00"
        image.save(output, format="JPEG", quality=65, exif=exif)
    else:
        image.save(output, format="JPEG", quality=65)
    return output.getvalue()


def _video_bytes(frame_count=6, fps=6, moving=True):
    path = None
    writer = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as output:
            path = output.name
        writer = cv2.VideoWriter(
            path, cv2.VideoWriter_fourcc(*"mp4v"), fps, (64, 48)
        )
        for index in range(frame_count):
            frame = np.zeros((48, 64, 3), dtype=np.uint8)
            frame[:, :, 0] = (80 + (index if moving else 0) * 10) % 256
            offset = index if moving else 0
            frame[10:38, 12 + offset:28 + offset, 1] = 220
            writer.write(frame)
        writer.release()
        writer = None
        with open(path, "rb") as video:
            return video.read()
    finally:
        if writer is not None:
            writer.release()
        if path:
            os.unlink(path)


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


def test_video_samples_frames_and_runs_forensics():
    result = analyze_media_file(
        "clip.mp4",
        "video/mp4",
        200_000,
        file_bytes=_video_bytes(),
    )

    assert result["forensic_metrics"]["video"]["sampled_frames"] == 6
    assert any(
        item["name"] == "Consistent forensic anomalies across sampled frames"
        for item in result["indicators"]
    )
    assert any(item["name"] == "Frame motion analysis" for item in result["indicators"]) is False
    assert any(item["name"] == "Frame-level model recommended" for item in result["indicators"])


def test_near_static_video_adds_conservative_motion_signal():
    result = analyze_media_file(
        "static.mp4", "video/mp4", 200_000, file_bytes=_video_bytes(moving=False)
    )

    assert any(item["name"] == "Frame motion analysis" for item in result["indicators"])


def test_corrupt_video_returns_graceful_indicator():
    result = analyze_media_file(
        "broken.mp4", "video/mp4", 12, file_bytes=b"not a video"
    )

    assert result["media_type"] == "Video"
    assert any(item["name"] == "Video frame extraction skipped" for item in result["indicators"])


def test_video_over_duration_cap_keeps_duration_heuristics():
    result = analyze_media_file(
        "long.mp4",
        "video/mp4",
        200_000,
        duration=VIDEO_MAX_DURATION_SECONDS + 1,
        file_bytes=_video_bytes(frame_count=301, fps=1),
    )

    assert not result["forensic_metrics"]
    assert any(item["name"] == "Video frame extraction skipped" for item in result["indicators"])
    assert any(item["name"] == "Frame-level model recommended" for item in result["indicators"])


def test_duration_only_video_heuristics_are_preserved():
    short = analyze_media_file("short.mp4", "video/mp4", 200_000, duration=2)
    long = analyze_media_file("long.mp4", "video/mp4", 200_000, duration=61)

    assert any(item["name"] == "Very short clip" for item in short["indicators"])
    assert not any(item["name"] == "Very short clip" for item in long["indicators"])


def test_normal_compressed_photo_stays_below_borderline_without_ml():
    file_bytes = _normal_photo_bytes()
    with patch(
        "scamshield.ai.detector.ImageForensicsService.analyze_image",
        return_value=_result(checked=False),
    ):
        result = analyze_media_file(
            "shared-photo.jpg", "image/jpeg", len(file_bytes), file_bytes=file_bytes
        )

    assert len(file_bytes) < 20_000
    assert result["ai_likelihood"] < 35
    assert result["risk_level"] != "May be AI-made"


def test_confident_real_ml_result_caps_normal_photo_score():
    file_bytes = _normal_photo_bytes()
    with patch(
        "scamshield.ai.detector.ImageForensicsService.analyze_image",
        return_value=_result(ai_probability=0.05),
    ):
        result = analyze_media_file(
            "shared-photo.jpg", "image/jpeg", len(file_bytes), file_bytes=file_bytes
        )

    assert result["ai_likelihood"] <= 20


def test_confident_ai_ml_result_overrides_clean_forensics():
    file_bytes = _normal_photo_bytes(with_exif=True)
    with patch(
        "scamshield.ai.detector.ImageForensicsService.analyze_image",
        return_value=_result(ai_probability=0.90),
    ):
        result = analyze_media_file(
            "camera-photo.jpg", "image/jpeg", 200_000, file_bytes=file_bytes
        )

    assert result["ai_likelihood"] >= 80
    assert result["risk_level"] == "May be AI-made"

"""Sightengine image AI-generation and deepfake detection integration."""

import os

import requests


SIGHTENGINE_URL = "https://api.sightengine.com/1.0/check.json"


def _empty_result(error=None):
    return {
        "checked": False,
        "ai_generated_probability": None,
        "deepfake_probability": None,
        "error": error,
    }


def _probability(value):
    try:
        probability = float(value)
    except (TypeError, ValueError):
        return None
    return probability if 0 <= probability <= 1 else None


class ImageForensicsService:
    """Run optional ML-based image checks through Sightengine."""

    def analyze_image(self, file_bytes: bytes, filename: str) -> dict:
        """Return normalized Sightengine results without raising network errors."""
        api_user = os.environ.get("SIGHTENGINE_API_USER", "")
        api_secret = os.environ.get("SIGHTENGINE_API_SECRET", "")
        if not api_user or not api_secret:
            return _empty_result("not_configured")

        try:
            response = requests.post(
                SIGHTENGINE_URL,
                params={
                    "models": "genai,deepfake",
                    "api_user": api_user,
                    "api_secret": api_secret,
                },
                files={"media": (filename or "image", file_bytes)},
                timeout=8,
            )
            response.raise_for_status()
            payload = response.json()
        except requests.RequestException as exc:
            return _empty_result(str(exc)[:160] or "request failed")
        except (ValueError, TypeError):
            return _empty_result("invalid JSON response")

        if not isinstance(payload, dict):
            return _empty_result("invalid JSON response")
        result_type = payload.get("type")
        if not isinstance(result_type, dict):
            result_type = {}

        return {
            "checked": True,
            "ai_generated_probability": _probability(result_type.get("ai_generated")),
            "deepfake_probability": _probability(result_type.get("deepfake")),
            "error": None,
        }
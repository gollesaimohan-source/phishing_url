from io import BytesIO


def test_media_upload_over_16mb_returns_json_413(client):
    response = client.post(
        "/api/analyze-media",
        data={"file": (BytesIO(b"x" * (16 * 1024 * 1024 + 1)), "large.bin")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 413
    assert response.is_json
    assert response.get_json() == {
        "success": False,
        "message": "Uploaded file is too large",
        "error": "Request Entity Too Large",
        "details": {"max_size_mb": 16},
    }

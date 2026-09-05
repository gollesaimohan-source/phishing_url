def test_api_rate_limit_blocks_after_threshold(app):
    app.config["API_RATE_LIMIT_MAX_REQUESTS"] = 3
    app.config["API_RATE_LIMIT_WINDOW_SECONDS"] = 60
    client = app.test_client()

    statuses = [client.get("/api/dashboard").status_code for _ in range(6)]

    # First 3 requests hit normal auth handling (401, unauthenticated).
    assert statuses[:3] == [401, 401, 401]
    # Requests beyond the budget are rate limited.
    assert 429 in statuses[3:]


def test_rate_limit_headers_present(app):
    app.config["API_RATE_LIMIT_MAX_REQUESTS"] = 5
    client = app.test_client()
    response = client.get("/api/dashboard")
    assert "X-RateLimit-Remaining" in response.headers
    assert "X-RateLimit-Limit" in response.headers


def test_empty_mongodb_uri_raises_in_strict_mode(app):
    from scamshield.repositories.database import get_database, reset_database_state
    from scamshield.repositories.exceptions import DatabaseConnectionError

    reset_database_state()
    app.config.update(MONGODB_URI="", MONGODB_STRICT=True)

    with app.app_context():
        with __import__("pytest").raises(DatabaseConnectionError, match="URI"):
            get_database()


def test_empty_mongodb_uri_uses_memory_in_non_strict_mode(app):
    from scamshield.repositories.database import get_database, reset_database_state

    reset_database_state()
    app.config.update(MONGODB_URI="", MONGODB_STRICT=False)

    with app.app_context():
        database = get_database()

    assert database is not None
    assert app.config["DATABASE_BACKEND"] == "memory"


def test_config_raises_in_production_with_default_secrets(monkeypatch):
    import importlib

    monkeypatch.setenv("DEBUG", "false")
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)

    from scamshield import config as config_module

    importlib.reload(config_module)
    try:
        with __import__("pytest").raises(RuntimeError):
            config_module.Config.validate()
    finally:
        monkeypatch.setenv("DEBUG", "true")
        monkeypatch.setenv("SECRET_KEY", "test-secret-key")
        monkeypatch.setenv("JWT_SECRET_KEY", "test-jwt-secret-key")
        importlib.reload(config_module)


def test_config_only_warns_in_debug_mode(monkeypatch):
    import importlib

    monkeypatch.setenv("DEBUG", "true")
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)

    from scamshield import config as config_module

    importlib.reload(config_module)
    try:
        warnings = config_module.Config.validate()
        assert any("SECRET_KEY" in w for w in warnings)
    finally:
        monkeypatch.setenv("SECRET_KEY", "test-secret-key")
        monkeypatch.setenv("JWT_SECRET_KEY", "test-jwt-secret-key")
        importlib.reload(config_module)

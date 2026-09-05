"""MongoDB connection, collection setup, and development fallback."""

from __future__ import annotations

from copy import deepcopy
import re
from typing import Any
from uuid import uuid4

from flask import Flask, current_app

from scamshield.repositories.exceptions import DatabaseConnectionError
from scamshield.utils.time import utc_now

try:
    from pymongo import ASCENDING, MongoClient
    from pymongo.errors import PyMongoError, ServerSelectionTimeoutError
except ImportError:  # pragma: no cover - exercised when dependencies are absent.
    ASCENDING = 1
    MongoClient = None
    PyMongoError = Exception
    ServerSelectionTimeoutError = Exception


COLLECTIONS = {
    "users": "users",
    "scans": "scans",
    "reports": "reports",
    "threat_intelligence": "threat_intelligence",
    "notifications": "notifications",
    "feedback": "feedback",
    "audit_logs": "audit_logs",
    "revoked_tokens": "revoked_tokens",
}

SEED_REPORTS = [
    {
        "report_id": "seed-report-1",
        "type": "UPI Fraud",
        "title": "Fake payment collect request",
        "location": "Hyderabad",
        "risk": "High",
        "status": "Verified",
        "created_at": "2026-05-25T10:30:00Z",
        "updated_at": "2026-05-25T10:30:00Z",
    }
]

_mongo_client: Any | None = None
_mongo_db: Any | None = None
_memory_db: "InMemoryDatabase | None" = None


class InMemoryCursor:
    """Small cursor adapter used by the local development fallback."""

    def __init__(self, documents: list[dict]) -> None:
        self._documents = documents

    def sort(self, field: str, direction: int) -> "InMemoryCursor":
        reverse = direction == -1
        self._documents.sort(key=lambda item: item.get(field, ""), reverse=reverse)
        return self

    def limit(self, count: int) -> "InMemoryCursor":
        self._documents = self._documents[:count]
        return self

    def skip(self, count: int) -> "InMemoryCursor":
        self._documents = self._documents[count:]
        return self

    def __iter__(self):
        return iter(self._documents)


class InMemoryCollection:
    """Minimal Mongo-like collection for local runs without Atlas."""

    def __init__(self, name: str) -> None:
        self.name = name
        self._documents: list[dict] = []
        self._indexes: list[tuple] = []

    def create_index(self, keys, unique: bool = False, sparse: bool = False) -> None:
        self._indexes.append((keys, unique, sparse))

    def count_documents(self, filter_query: dict | None = None) -> int:
        return len(list(self.find(filter_query or {})))

    def insert_one(self, document: dict):
        stored = deepcopy(document)
        stored.setdefault("_id", str(uuid4()))
        self._documents.append(stored)

        class Result:
            inserted_id = stored["_id"]

        return Result()

    def find(self, filter_query: dict | None = None, projection: dict | None = None):
        matches = [
            deepcopy(document)
            for document in self._documents
            if _matches_filter(document, filter_query or {})
        ]
        if projection:
            matches = [_apply_projection(document, projection) for document in matches]
        return InMemoryCursor(matches)

    def update_one(self, filter_query: dict, update: dict, upsert: bool = False):
        for document in self._documents:
            if _matches_filter(document, filter_query):
                document.update(update.get("$set", {}))
                return None
        if upsert:
            document = dict(filter_query)
            document.update(update.get("$set", {}))
            self.insert_one(document)
        return None

    def delete_one(self, filter_query: dict):
        for index, document in enumerate(self._documents):
            if _matches_filter(document, filter_query):
                self._documents.pop(index)
                deleted_count = 1
                break
        else:
            deleted_count = 0

        class Result:
            pass

        result = Result()
        result.deleted_count = deleted_count
        return result


class InMemoryDatabase:
    """Mongo-like database adapter for development fallback."""

    def __init__(self) -> None:
        self._collections = {
            name: InMemoryCollection(name) for name in COLLECTIONS.values()
        }

    def __getitem__(self, name: str) -> InMemoryCollection:
        return self._collections[name]

    def command(self, command_name: str) -> dict:
        return {"ok": 1, "command": command_name}


def _matches_filter(document: dict, filter_query: dict) -> bool:
    for key, value in filter_query.items():
        if key == "$or":
            if not any(_matches_filter(document, option) for option in value):
                return False
            continue
        if key == "$and":
            if not all(_matches_filter(document, option) for option in value):
                return False
            continue

        if isinstance(value, dict):
            if "$regex" in value:
                flags = re.IGNORECASE if "i" in value.get("$options", "") else 0
                if not re.search(str(value["$regex"]), str(document.get(key, "")), flags):
                    return False
                continue

        if document.get(key) != value:
            return False
    return True


def _apply_projection(document: dict, projection: dict) -> dict:
    if projection.get("_id") == 0:
        document.pop("_id", None)
    return document


def init_db(app: Flask) -> None:
    """Initialize MongoDB collections, indexes, and seed data."""
    with app.app_context():
        database = get_database()
        create_indexes(database)
        seed_database(database)
        app.logger.info(
            "database_initialized backend=%s name=%s",
            current_app.config["DATABASE_BACKEND"],
            current_app.config["DATABASE_NAME"],
        )


def get_database():
    """Return the configured MongoDB database handle."""
    global _mongo_client, _mongo_db, _memory_db

    if _mongo_db is not None:
        return _mongo_db

    uri = current_app.config["MONGODB_URI"]
    if not uri:
        if current_app.config["MONGODB_STRICT"]:
            raise DatabaseConnectionError("MongoDB URI is not configured")
        return _use_memory_fallback(
            "mongodb_uri_missing using in-memory development database"
        )

    if MongoClient is None:
        current_app.logger.error("pymongo_not_installed")
        return _use_memory_fallback("pymongo_not_installed using in-memory database")

    try:
        _mongo_client = MongoClient(
            uri,
            serverSelectionTimeoutMS=current_app.config["MONGODB_TIMEOUT_MS"],
            uuidRepresentation="standard",
        )
        _mongo_client.admin.command("ping")
        _mongo_db = _mongo_client[current_app.config["DATABASE_NAME"]]
        current_app.config["DATABASE_BACKEND"] = "mongodb"
        current_app.logger.info(
            "mongodb_connected database=%s", current_app.config["DATABASE_NAME"]
        )
        return _mongo_db
    except ServerSelectionTimeoutError as error:
        current_app.logger.exception("mongodb_timeout")
        # Surface a readable reason so health endpoint can indicate the memory fallback
        try:
            current_app.config["DATABASE_BACKEND_REASON"] = "memory-fallback"
        except Exception:
            # ignore if app context changes
            pass
        if not current_app.config["MONGODB_STRICT"]:
            return _use_memory_fallback("mongodb_timeout using in-memory database")
        raise DatabaseConnectionError("MongoDB connection timed out") from error
    except PyMongoError as error:
        current_app.logger.exception("mongodb_connection_failed")
        if not current_app.config["MONGODB_STRICT"]:
            return _use_memory_fallback(
                "mongodb_connection_failed using in-memory database"
            )
        raise DatabaseConnectionError("MongoDB connection failed") from error


def get_collection(collection_name: str):
    """Return a named MongoDB collection."""
    return get_database()[collection_name]


def _use_memory_fallback(reason: str):
    """Switch to the in-memory fallback database."""
    global _memory_db, _mongo_db
    current_app.logger.warning(reason)
    current_app.config["DATABASE_BACKEND"] = "memory"
    _memory_db = _memory_db or InMemoryDatabase()
    _mongo_db = _memory_db
    return _mongo_db


def create_indexes(database) -> None:
    """Create required indexes for all ScamShield collections."""
    database[COLLECTIONS["users"]].create_index(
        [("email", ASCENDING)], unique=True, sparse=True
    )
    database[COLLECTIONS["users"]].create_index(
        [("username", ASCENDING)], unique=True, sparse=True
    )
    database[COLLECTIONS["scans"]].create_index(
        [("scan_id", ASCENDING)], unique=True
    )
    database[COLLECTIONS["scans"]].create_index([("url", ASCENDING)])
    database[COLLECTIONS["scans"]].create_index([("created_at", ASCENDING)])
    database[COLLECTIONS["reports"]].create_index(
        [("report_id", ASCENDING)], unique=True
    )
    database[COLLECTIONS["reports"]].create_index([("created_at", ASCENDING)])
    database[COLLECTIONS["threat_intelligence"]].create_index(
        [("domain", ASCENDING)], unique=True, sparse=True
    )
    database[COLLECTIONS["threat_intelligence"]].create_index(
        [("created_at", ASCENDING)]
    )
    database[COLLECTIONS["threat_intelligence"]].create_index(
        [("highest_risk", ASCENDING)]
    )
    database[COLLECTIONS["notifications"]].create_index([("created_at", ASCENDING)])
    database[COLLECTIONS["feedback"]].create_index([("created_at", ASCENDING)])
    database[COLLECTIONS["audit_logs"]].create_index([("created_at", ASCENDING)])
    database[COLLECTIONS["revoked_tokens"]].create_index(
        [("jti", ASCENDING)], unique=True
    )
    database[COLLECTIONS["revoked_tokens"]].create_index([("expires_at", ASCENDING)])
    current_app.logger.info("mongodb_indexes_ensured")


def seed_database(database) -> None:
    """Seed demo report data if the reports collection is empty."""
    reports = database[COLLECTIONS["reports"]]
    if reports.count_documents({}) > 0:
        return

    for report in SEED_REPORTS:
        reports.insert_one(dict(report))
    current_app.logger.info("seed_reports_inserted count=%s", len(SEED_REPORTS))


def reset_database_state() -> None:
    """Clear cached database handles. Intended for use in tests only."""
    global _mongo_client, _mongo_db, _memory_db
    _mongo_client = None
    _mongo_db = None
    _memory_db = None


def now_document() -> dict:
    """Return created/updated timestamps for new MongoDB documents."""
    timestamp = utc_now()
    return {"created_at": timestamp, "updated_at": timestamp}

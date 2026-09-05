"""Centralized JSON error handling."""

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

from scamshield.repositories.exceptions import (
    DatabaseConnectionError,
    DatabaseTimeoutError,
    DuplicateRecordError,
    RepositoryError,
    RepositoryValidationError,
)
from scamshield.validators.exceptions import ValidationError


def register_error_handlers(app: Flask) -> None:
    """Register JSON error handlers for predictable API responses."""

    @app.errorhandler(ValidationError)
    def handle_validation_error(error: ValidationError):
        app.logger.warning("validation_error message=%s", str(error))
        details = error.args[0] if error.args and isinstance(error.args[0], dict) else {}
        message = "Validation failed" if details else str(error)
        return (
            jsonify(
                {
                    "success": False,
                    "message": message,
                    "error": message,
                    "details": details,
                }
            ),
            400,
        )

    @app.errorhandler(RepositoryValidationError)
    def handle_repository_validation_error(error: RepositoryValidationError):
        app.logger.warning("repository_validation_error message=%s", str(error))
        return jsonify({"success": False, "message": str(error), "error": str(error)}), 400

    @app.errorhandler(DuplicateRecordError)
    def handle_duplicate_record_error(error: DuplicateRecordError):
        app.logger.warning("duplicate_record_error message=%s", str(error))
        return (
            jsonify(
                {
                    "success": False,
                    "message": "A record with the same unique value already exists",
                    "error": str(error),
                }
            ),
            409,
        )

    @app.errorhandler(DatabaseTimeoutError)
    def handle_database_timeout_error(error: DatabaseTimeoutError):
        app.logger.error("database_timeout_error message=%s", str(error))
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Database operation timed out",
                    "error": str(error),
                }
            ),
            504,
        )

    @app.errorhandler(DatabaseConnectionError)
    def handle_database_connection_error(error: DatabaseConnectionError):
        app.logger.error("database_connection_error message=%s", str(error))
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Database connection failed",
                    "error": str(error),
                }
            ),
            503,
        )

    @app.errorhandler(RepositoryError)
    def handle_repository_error(error: RepositoryError):
        app.logger.error("repository_error message=%s", str(error))
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Database operation failed",
                    "error": str(error),
                }
            ),
            500,
        )

    @app.errorhandler(HTTPException)
    def handle_http_error(error: HTTPException):
        app.logger.warning("http_error status=%s message=%s", error.code, error.description)
        return (
            jsonify(
                {
                    "success": False,
                    "message": error.description,
                    "error": error.name,
                }
            ),
            error.code,
        )

    @app.errorhandler(RequestEntityTooLarge)
    def handle_request_entity_too_large(error: RequestEntityTooLarge):
        app.logger.warning("request_entity_too_large path=%s", request.path)
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Uploaded file is too large",
                    "error": "Request Entity Too Large",
                    "details": {"max_size_mb": 16},
                }
            ),
            413,
        )

    @app.errorhandler(Exception)
    def handle_unexpected_error(error: Exception):
        app.logger.exception("unexpected_exception message=%s", str(error))
        return (
            jsonify(
                {
                    "success": False,
                    "message": "An unexpected error occurred",
                    "error": "Internal Server Error",
                }
            ),
            500,
        )

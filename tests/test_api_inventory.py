"""Tests for the api_inventory module: OpenAPI parser + CLI ingest."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from drake_x.normalize.openapi import SpecParseError, parse_openapi_file


# ----- sample specs ----------------------------------------------------------


def _openapi3_spec() -> dict:
    return {
        "openapi": "3.0.3",
        "info": {"title": "Pet Store", "version": "1.2.0"},
        "servers": [{"url": "https://api.example.com/v2"}],
        "paths": {
            "/pets": {
                "get": {
                    "summary": "List pets",
                    "operationId": "listPets",
                    "tags": ["pets"],
                    "parameters": [
                        {"name": "limit", "in": "query", "required": False},
                    ],
                    "security": [{"bearerAuth": []}],
                },
                "post": {
                    "summary": "Create a pet",
                    "operationId": "createPet",
                    "tags": ["pets"],
                    "requestBody": {
                        "content": {
                            "application/json": {},
                        },
                    },
                },
            },
            "/pets/{petId}": {
                "parameters": [
                    {"name": "petId", "in": "path", "required": True},
                ],
                "get": {
                    "summary": "Get a pet",
                    "operationId": "getPet",
                    "deprecated": True,
                },
                "delete": {
                    "summary": "Delete a pet",
                },
            },
        },
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                },
            },
        },
    }


def _swagger2_spec() -> dict:
    return {
        "swagger": "2.0",
        "info": {"title": "Old API", "version": "0.9"},
        "host": "legacy.example.com",
        "basePath": "/api",
        "schemes": ["https"],
        "paths": {
            "/items": {
                "get": {"summary": "List items"},
            },
        },
        "securityDefinitions": {
            "apiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
        },
    }


# ----- parser tests ----------------------------------------------------------


def test_parse_openapi3_json(tmp_path: Path) -> None:
    p = tmp_path / "spec.json"
    p.write_text(json.dumps(_openapi3_spec()), encoding="utf-8")
    art = parse_openapi_file(p)
    assert art.kind == "api.inventory"
    assert art.confidence >= 0.85
    assert art.payload["spec_version"] == "3.0.3"
    assert art.payload["title"] == "Pet Store"
    assert art.payload["endpoint_count"] == 4
    # Endpoints should cover GET/POST /pets and GET/DELETE /pets/{petId}
    methods = {(e["path"], e["method"]) for e in art.payload["endpoints"]}
    assert ("/pets", "GET") in methods
    assert ("/pets", "POST") in methods
    assert ("/pets/{petId}", "GET") in methods
    assert ("/pets/{petId}", "DELETE") in methods


def test_parse_openapi3_extracts_parameters(tmp_path: Path) -> None:
    p = tmp_path / "spec.json"
    p.write_text(json.dumps(_openapi3_spec()), encoding="utf-8")
    art = parse_openapi_file(p)
    get_pets = next(
        e for e in art.payload["endpoints"] if e["path"] == "/pets" and e["method"] == "GET"
    )
    param_names = [p["name"] for p in get_pets["parameters"]]
    assert "limit" in param_names


def test_parse_openapi3_extracts_request_body_types(tmp_path: Path) -> None:
    p = tmp_path / "spec.json"
    p.write_text(json.dumps(_openapi3_spec()), encoding="utf-8")
    art = parse_openapi_file(p)
    post_pets = next(
        e for e in art.payload["endpoints"] if e["path"] == "/pets" and e["method"] == "POST"
    )
    assert "application/json" in post_pets["request_body_types"]


def test_parse_openapi3_extracts_security_schemes(tmp_path: Path) -> None:
    p = tmp_path / "spec.json"
    p.write_text(json.dumps(_openapi3_spec()), encoding="utf-8")
    art = parse_openapi_file(p)
    assert "bearerAuth" in art.payload["security_schemes"]


def test_parse_openapi3_detects_deprecated_endpoints(tmp_path: Path) -> None:
    p = tmp_path / "spec.json"
    p.write_text(json.dumps(_openapi3_spec()), encoding="utf-8")
    art = parse_openapi_file(p)
    get_pet = next(
        e for e in art.payload["endpoints"] if e["operation_id"] == "getPet"
    )
    assert get_pet["deprecated"] is True


def test_parse_openapi3_path_level_params_merge_to_operations(tmp_path: Path) -> None:
    p = tmp_path / "spec.json"
    p.write_text(json.dumps(_openapi3_spec()), encoding="utf-8")
    art = parse_openapi_file(p)
    get_pet = next(
        e for e in art.payload["endpoints"]
        if e["path"] == "/pets/{petId}" and e["method"] == "GET"
    )
    param_names = [pp["name"] for pp in get_pet["parameters"]]
    assert "petId" in param_names


def test_parse_swagger2_json(tmp_path: Path) -> None:
    p = tmp_path / "swagger.json"
    p.write_text(json.dumps(_swagger2_spec()), encoding="utf-8")
    art = parse_openapi_file(p)
    assert art.payload["spec_version"] == "2.0"
    assert art.payload["servers"] == ["https://legacy.example.com/api"]
    assert art.payload["endpoint_count"] == 1
    assert "apiKey" in art.payload["security_schemes"]


def test_parse_empty_paths_low_confidence(tmp_path: Path) -> None:
    spec = {"openapi": "3.0.0", "info": {"title": "Empty", "version": "0"}, "paths": {}}
    p = tmp_path / "empty.json"
    p.write_text(json.dumps(spec), encoding="utf-8")
    art = parse_openapi_file(p)
    assert art.payload["endpoint_count"] == 0
    assert art.confidence < 0.5
    assert any("no endpoints" in n for n in art.notes)


def test_parse_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(SpecParseError, match="not found"):
        parse_openapi_file(tmp_path / "nope.json")


def test_parse_invalid_json_raises(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text("not json", encoding="utf-8")
    with pytest.raises(SpecParseError):
        parse_openapi_file(p)

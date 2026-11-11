"""app/security.py testleri -- DB gerektirmez (master_prompt.md 5 'CSP')."""

import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.security import SecurityHeadersMiddleware  # noqa: E402


@pytest.fixture()
def client():
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/x")
    def x():
        return {"ok": True}

    return TestClient(app)


def test_content_security_policy_header_present(client):
    resp = client.get("/x")
    csp = resp.headers.get("content-security-policy", "")
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp


def test_csp_script_src_is_self_only_no_cdn(client):
    """Panelin tum JS'i kendi kodumuzdur (app/static/) -- CSP script-src'de
    hicbir CDN/harici origin OLMAMALI."""
    resp = client.get("/x")
    csp = resp.headers.get("content-security-policy", "")
    assert "script-src 'self'" in csp


def test_x_content_type_options_nosniff(client):
    resp = client.get("/x")
    assert resp.headers.get("x-content-type-options") == "nosniff"


def test_x_frame_options_deny(client):
    resp = client.get("/x")
    assert resp.headers.get("x-frame-options") == "DENY"


def test_referrer_policy_no_referrer(client):
    resp = client.get("/x")
    assert resp.headers.get("referrer-policy") == "no-referrer"

"""app/csrf.py testleri -- DB gerektirmez, izole bir FastAPI app uzerinde
double-submit cookie desenini dogrular (master_prompt.md 5 'CSRF/CSP')."""

import sys
from pathlib import Path

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.csrf import CSRF_COOKIE_NAME, ensure_csrf_token, require_csrf, set_csrf_cookie  # noqa: E402
from starlette.requests import Request  # noqa: E402


def _build_app() -> FastAPI:
    app = FastAPI()

    @app.get("/form")
    def form(request: Request):
        token, is_new = ensure_csrf_token(request)
        from starlette.responses import JSONResponse

        response = JSONResponse({"csrf_token": token})
        if is_new:
            set_csrf_cookie(response, token, cookie_secure=False)
        return response

    @app.post("/mutate")
    def mutate(_csrf: None = Depends(require_csrf)):
        return {"status": "ok"}

    return app


@pytest.fixture()
def client():
    return TestClient(_build_app())


def test_get_request_issues_csrf_cookie(client):
    resp = client.get("/form")
    assert resp.status_code == 200
    assert CSRF_COOKIE_NAME in resp.cookies
    assert resp.json()["csrf_token"] == resp.cookies[CSRF_COOKIE_NAME]


def test_repeated_get_reuses_same_cookie(client):
    first = client.get("/form")
    token1 = first.json()["csrf_token"]
    second = client.get("/form")
    token2 = second.json()["csrf_token"]
    assert token1 == token2


def test_post_without_csrf_token_is_rejected(client):
    resp = client.post("/mutate")
    assert resp.status_code == 403


def test_post_with_cookie_but_no_form_field_is_rejected(client):
    form_resp = client.get("/form")
    token = form_resp.json()["csrf_token"]
    client.cookies.set(CSRF_COOKIE_NAME, token)
    resp = client.post("/mutate")
    assert resp.status_code == 403


def test_post_with_matching_cookie_and_form_field_succeeds(client):
    form_resp = client.get("/form")
    token = form_resp.json()["csrf_token"]
    client.cookies.set(CSRF_COOKIE_NAME, token)
    resp = client.post("/mutate", data={"csrf_token": token})
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_post_with_matching_cookie_and_header_succeeds(client):
    form_resp = client.get("/form")
    token = form_resp.json()["csrf_token"]
    client.cookies.set(CSRF_COOKIE_NAME, token)
    resp = client.post("/mutate", headers={"X-CSRF-Token": token})
    assert resp.status_code == 200


def test_post_with_mismatched_token_is_rejected(client):
    form_resp = client.get("/form")
    token = form_resp.json()["csrf_token"]
    client.cookies.set(CSRF_COOKIE_NAME, token)
    resp = client.post("/mutate", data={"csrf_token": "attacker-guessed-value"})
    assert resp.status_code == 403


def test_post_with_forged_cookie_and_matching_field_is_rejected_without_real_cookie(client):
    """Saldirgan cross-origin formla hem cookie hem alani KENDI secebilse
    bile (bu testte simule edilmiyor -- SOP zaten bunu engeller), sunucu
    TARAYICININ GONDERDIGI GERCEK cookie'ye bakar: cookie hic yoksa ret."""
    resp = client.post("/mutate", data={"csrf_token": "whatever-attacker-wants"})
    assert resp.status_code == 403

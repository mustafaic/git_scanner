"""Aşama 3 panel entegrasyon testleri -- gerçek Postgres gerektirir
(master_prompt.md 5: auth, RBAC, audit log, CSRF, API token). DATABASE_URL
ayarlı değilse (lokal, docker dışı) atlanır -- bkz. test-runner servisi
(deploy/docker-compose.yml, postgres-test DB'sine bağlı).

KRİTİK: `from app.main import app` SADECE DATABASE_URL ayarlıysa yapılır --
app/main.py import zamanında `load_settings()` + `init_engine()` çağırır,
env yoksa pydantic ValidationError fırlatır ve pytest TOPLAMA (collection)
aşamasında -- skipif'in devreye girmesinden ÖNCE -- çöker."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pyotp
import pytest
from sqlalchemy import create_engine, text

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

DATABASE_URL = os.environ.get("DATABASE_URL")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL ayarli degil (gercek Postgres gerekir)")

if DATABASE_URL:
    os.environ.setdefault("SESSION_COOKIE_SECURE", "false")

    from fastapi.testclient import TestClient

    from app.csrf import CSRF_COOKIE_NAME
    from app.main import app
    from core import auth
    from core.models import AuditLog, Finding, Repository, SecretFinding, User


ADMIN_PASSWORD = "Str0ng!Passw0rd#2026"
VIEWER_PASSWORD = "An0therStr0ng!Pw#2026"


@pytest.fixture()
def engine():
    eng = create_engine(DATABASE_URL, future=True)
    yield eng
    eng.dispose()


@pytest.fixture(autouse=True)
def _clean(engine):
    with engine.begin() as conn:
        for table in (
            "secret_finding_events", "secret_findings", "finding_events", "finding_sources", "findings",
            "api_tokens", "audit_log", "sessions", "users", "repositories", "scan_triggers",
        ):
            conn.execute(text(f"DELETE FROM {table}"))
    yield


@pytest.fixture()
def client():
    return TestClient(app)


def _make_admin(engine, username="admin"):
    secret = auth.generate_totp_secret()
    from sqlalchemy.orm import sessionmaker

    Session = sessionmaker(bind=engine, future=True)
    with Session() as session:
        user = User(
            username=username, password_hash=auth.hash_password(ADMIN_PASSWORD), role="admin",
            totp_secret=secret, totp_enabled=True,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        return user.id, secret


def _make_viewer(engine, username="viewer"):
    from sqlalchemy.orm import sessionmaker

    Session = sessionmaker(bind=engine, future=True)
    with Session() as session:
        user = User(username=username, password_hash=auth.hash_password(VIEWER_PASSWORD), role="viewer")
        session.add(user)
        session.commit()
        session.refresh(user)
        return user.id


def _login(client, username, password, totp_code=""):
    client.get("/login")
    # ensure_csrf_token() SADECE cookie HENUZ yoksa Set-Cookie yazar --
    # tekrarlanan login cagrilarinda (ör. kilitleme testi) ikinci+ GET
    # /login cevabinda cookie YOKTUR (zaten vardi), bu yuzden deger
    # KALICI cookie jar'indan (client.cookies) okunmali, response'tan degil.
    token = client.cookies.get(CSRF_COOKIE_NAME)
    return client.post(
        "/login", data={"username": username, "password": password, "totp_code": totp_code, "csrf_token": token},
        follow_redirects=False,
    )


def _csrf_token(client):
    resp = client.get("/")
    return resp.cookies.get(CSRF_COOKIE_NAME) or client.cookies.get(CSRF_COOKIE_NAME)


def test_login_flow_success_failure_lockout_and_audit(client, engine):
    _, secret = _make_admin(engine)
    code = pyotp.TOTP(secret).now()

    resp = _login(client, "admin", "wrong-password", code)
    assert resp.status_code == 401

    resp_ok = _login(client, "admin", ADMIN_PASSWORD, code)
    assert resp_ok.status_code == 303
    assert "session_id" in resp_ok.cookies

    with engine.begin() as conn:
        actions = [r[0] for r in conn.execute(text("SELECT action FROM audit_log ORDER BY id")).fetchall()]
    assert "login_failed" in actions
    assert "login_success" in actions


def test_login_lockout_after_max_failed_attempts(client, engine):
    _make_admin(engine)
    for _ in range(auth.MAX_FAILED_LOGIN_ATTEMPTS):
        _login(client, "admin", "wrong-password")
    resp = _login(client, "admin", ADMIN_PASSWORD, "000000")
    assert resp.status_code == 401
    assert "kilitli" in resp.text


def test_login_rejects_without_csrf_token(client, engine):
    _make_admin(engine)
    client.get("/login")
    resp = client.post("/login", data={"username": "admin", "password": ADMIN_PASSWORD, "totp_code": ""})
    assert resp.status_code == 403


def test_viewer_login_without_totp_succeeds(client, engine):
    _make_viewer(engine)
    resp = _login(client, "viewer", VIEWER_PASSWORD)
    assert resp.status_code == 303


def test_unauthenticated_dashboard_redirects_to_login(client):
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/login")


def test_viewer_cannot_change_finding_status_admin_can(client, engine):
    viewer_id = _make_viewer(engine)
    admin_id, secret = _make_admin(engine)

    from sqlalchemy.orm import sessionmaker

    Session = sessionmaker(bind=engine, future=True)
    with Session() as session:
        session.add(Repository(
            github_repo_id=1, full_name="acme/widgets", owner="acme", name="widgets",
            default_branch="main", visibility="private",
        ))
        finding = Finding(
            repo_id=1, lockfile_path="package-lock.json", ecosystem="npm", package_name="lodash",
            version="4.17.15", canonical_vulnerability_id="GHSA-xxxx", verification_status="VERIFIED",
            lifecycle_status="OPEN",
        )
        session.add(finding)
        session.commit()
        finding_id = finding.id

    _login(client, "viewer", VIEWER_PASSWORD)
    token = _csrf_token(client)
    resp = client.post(
        f"/findings/{finding_id}/status",
        data={"new_status": "FALSE_POSITIVE", "reason": "test", "csrf_token": token},
    )
    assert resp.status_code == 403

    client.post("/logout", data={"csrf_token": token})
    code = pyotp.TOTP(secret).now()
    _login(client, "admin", ADMIN_PASSWORD, code)
    token = _csrf_token(client)
    resp = client.post(
        f"/findings/{finding_id}/status",
        data={"new_status": "FALSE_POSITIVE", "reason": "gercek degil", "csrf_token": token},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    with engine.begin() as conn:
        status = conn.execute(text("SELECT lifecycle_status FROM findings WHERE id=:i"), {"i": finding_id}).scalar_one()
        event_count = conn.execute(text("SELECT count(*) FROM finding_events WHERE finding_id=:i"), {"i": finding_id}).scalar_one()
        audit_count = conn.execute(
            text("SELECT count(*) FROM audit_log WHERE action='finding_status_changed'")
        ).scalar_one()
    assert status == "FALSE_POSITIVE"
    assert event_count == 1
    assert audit_count == 1


def test_finding_status_cannot_be_set_to_resolved_manually(client, engine):
    _, secret = _make_admin(engine)
    from sqlalchemy.orm import sessionmaker

    Session = sessionmaker(bind=engine, future=True)
    with Session() as session:
        session.add(Repository(
            github_repo_id=1, full_name="acme/widgets", owner="acme", name="widgets",
            default_branch="main", visibility="private",
        ))
        finding = Finding(
            repo_id=1, lockfile_path="package-lock.json", ecosystem="npm", package_name="lodash",
            version="4.17.15", canonical_vulnerability_id="GHSA-xxxx", verification_status="VERIFIED",
            lifecycle_status="OPEN",
        )
        session.add(finding)
        session.commit()
        finding_id = finding.id

    code = pyotp.TOTP(secret).now()
    _login(client, "admin", ADMIN_PASSWORD, code)
    token = _csrf_token(client)
    resp = client.post(
        f"/findings/{finding_id}/status", data={"new_status": "RESOLVED", "reason": "x", "csrf_token": token},
    )
    assert resp.status_code == 400


def test_secret_rotation_sets_rotated_fields_and_audit(client, engine):
    admin_id, secret = _make_admin(engine)
    from sqlalchemy.orm import sessionmaker

    Session = sessionmaker(bind=engine, future=True)
    with Session() as session:
        session.add(Repository(
            github_repo_id=2, full_name="acme/secrets-demo", owner="acme", name="secrets-demo",
            default_branch="main", visibility="private",
        ))
        sf = SecretFinding(
            repo_id=2, rule_id="aws-access-key", file_path="config/prod.env",
            custom_fingerprint="fp-1", secret_content_hash="hash-1", present_in_current_code=False,
            lifecycle_status="OPEN",
        )
        session.add(sf)
        session.commit()
        secret_id = sf.id

    code = pyotp.TOTP(secret).now()
    _login(client, "admin", ADMIN_PASSWORD, code)
    token = _csrf_token(client)
    resp = client.post(
        f"/secrets/{secret_id}/status",
        data={"new_status": "ROTATED", "note": "AWS key rotated, ticket #42", "csrf_token": token},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT lifecycle_status, rotated_at, rotated_by_user_id FROM secret_findings WHERE id=:i"), {"i": secret_id}
        ).one()
    assert row[0] == "ROTATED"
    assert row[1] is not None
    assert row[2] == admin_id


def test_audit_log_page_admin_only(client, engine):
    _make_viewer(engine)
    _login(client, "viewer", VIEWER_PASSWORD)
    resp = client.get("/audit-log")
    assert resp.status_code == 403


def test_api_token_created_in_panel_authorizes_api_and_revocation_blocks_it(client, engine):
    _make_viewer(engine)
    _login(client, "viewer", VIEWER_PASSWORD)
    token = _csrf_token(client)
    resp = client.post("/tokens", data={"name": "ci", "expires_in_days": "", "csrf_token": token})
    assert resp.status_code == 200
    assert "Yeni token" in resp.text or "secret" in resp.text

    import re

    match = re.search(r'<code class="secret">([^<]+)</code>', resp.text)
    assert match is not None
    raw_token = match.group(1)

    api_client_resp = client.get("/api/findings", headers={"Authorization": f"Bearer {raw_token}"})
    assert api_client_resp.status_code == 200
    assert api_client_resp.json() == []

    no_auth_resp = client.get("/api/findings")
    assert no_auth_resp.status_code == 401

    with engine.begin() as conn:
        last_used = conn.execute(text("SELECT last_used_at FROM api_tokens WHERE name='ci'")).scalar_one()
    assert last_used is not None

    token_id = None
    with engine.begin() as conn:
        token_id = conn.execute(text("SELECT id FROM api_tokens WHERE name='ci'")).scalar_one()
    revoke_resp = client.post(f"/tokens/{token_id}/revoke", data={"csrf_token": token}, follow_redirects=False)
    assert revoke_resp.status_code == 303

    revoked_api_resp = client.get("/api/findings", headers={"Authorization": f"Bearer {raw_token}"})
    assert revoked_api_resp.status_code == 401


def test_logout_revokes_session(client, engine):
    _make_viewer(engine)
    _login(client, "viewer", VIEWER_PASSWORD)
    token = _csrf_token(client)
    assert client.get("/").status_code == 200

    client.post("/logout", data={"csrf_token": token})
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/login")


def test_raw_secret_value_never_appears_in_html_or_api(client, engine):
    """master_prompt.md Asama 3 kabul kriteri: 'ham secret hicbir yerde
    gorunmez (DB dump, log, API, HTML uzerinde otomatik kontrol testi)'.
    adapters/gitleaks.py zaten parse() siniri icin bunu test ediyor
    (tests/unit/test_gitleaks_adapter.py); burada panel katmani (HTML
    detay sayfasi + JSON API) icin ayni garantiyi dogruluyoruz. Ham
    deger SecretFinding'de SUTUN OLARAK HIC YOK -- bu test, yanlislikla
    (ör. ileride) bir debug alaninda sizdirilmadigini kanitlar."""
    import hashlib

    raw_secret = "ghp_ThisIsAFakeButRealisticLookingTokenForTestingOnly123456"
    content_hash = hashlib.sha256(raw_secret.encode("utf-8")).hexdigest()

    admin_id, secret = _make_admin(engine)
    from sqlalchemy.orm import sessionmaker

    Session = sessionmaker(bind=engine, future=True)
    with Session() as session:
        session.add(Repository(
            github_repo_id=3, full_name="acme/leak-check", owner="acme", name="leak-check",
            default_branch="main", visibility="private",
        ))
        sf = SecretFinding(
            repo_id=3, rule_id="github-pat", file_path="settings.py",
            custom_fingerprint="fp-leak-check", secret_content_hash=content_hash,
            gitleaks_fingerprint="deadbeef:settings.py:github-pat:2", lifecycle_status="OPEN",
        )
        session.add(sf)
        session.commit()
        secret_id = sf.id

    code = pyotp.TOTP(secret).now()
    _login(client, "admin", ADMIN_PASSWORD, code)

    html_resp = client.get(f"/secrets/{secret_id}")
    assert html_resp.status_code == 200
    assert raw_secret not in html_resp.text
    assert content_hash in html_resp.text  # hash GORUNUR olmali, ham deger DEGIL

    list_resp = client.get("/secrets")
    assert raw_secret not in list_resp.text

    token = _csrf_token(client)
    token_resp = client.post("/tokens", data={"name": "leak-check", "expires_in_days": "", "csrf_token": token})
    import re

    match = re.search(r'<code class="secret">([^<]+)</code>', token_resp.text)
    api_token = match.group(1)

    api_resp = client.get("/api/secret-findings", headers={"Authorization": f"Bearer {api_token}"})
    assert api_resp.status_code == 200
    body_text = api_resp.text
    assert raw_secret not in body_text
    for item in api_resp.json():
        assert "secret_content_hash" not in item  # API bile hash'i donmuyor (ihtiyac yok)
        for value in item.values():
            assert value != raw_secret


def test_viewer_can_only_reach_own_token_write_endpoints_all_other_writes_blocked(client, engine):
    """master_prompt.md Asama 3 kabul kriteri: 'viewer hicbir yazma uc
    noktasina erisemez' -- KULLANICI KARARI (bkz. docs/ASSUMPTIONS.md):
    bu kuralin TEK istisnasi viewer'in KENDI read-only API token'ini
    olusturup iptal etmesidir (yetki yukselmesi degil -- panelde zaten
    gordugu veriyi baska bir kanaldan cekmek icin). Asagidaki TUM diger
    yazma uc noktalari viewer icin 401/403/404 ile reddedilmeli."""
    viewer_id = _make_viewer(engine)
    admin_id, _ = _make_admin(engine)

    from sqlalchemy.orm import sessionmaker

    Session = sessionmaker(bind=engine, future=True)
    with Session() as session:
        session.add(Repository(
            github_repo_id=4, full_name="acme/rbac-check", owner="acme", name="rbac-check",
            default_branch="main", visibility="private",
        ))
        finding = Finding(
            repo_id=4, lockfile_path="package-lock.json", ecosystem="npm", package_name="lodash",
            version="4.17.15", canonical_vulnerability_id="GHSA-xxxx", verification_status="VERIFIED",
            lifecycle_status="OPEN",
        )
        sf = SecretFinding(
            repo_id=4, rule_id="aws-access-key", file_path="x.env",
            custom_fingerprint="fp-rbac-check", secret_content_hash="hash-rbac-check", lifecycle_status="OPEN",
        )
        session.add_all([finding, sf])
        session.commit()
        finding_id, secret_id = finding.id, sf.id

    _login(client, "viewer", VIEWER_PASSWORD)
    csrf = _csrf_token(client)

    write_requests = [
        ("post", f"/findings/{finding_id}/status", {"new_status": "FALSE_POSITIVE", "reason": "x", "csrf_token": csrf}),
        ("post", f"/secrets/{secret_id}/status", {"new_status": "ROTATED", "note": "x", "csrf_token": csrf}),
        ("post", "/repositories/4/trigger", {"csrf_token": csrf}),
    ]
    for method, path, data in write_requests:
        resp = getattr(client, method)(path, data=data, follow_redirects=False)
        assert resp.status_code == 403, f"{method.upper()} {path} viewer'a 403 vermeli, {resp.status_code} dondu"

    audit_resp = client.get("/audit-log")
    assert audit_resp.status_code == 403

    # TEK istisna (kullanici karari): kendi read-only API token'ini yonetmek.
    token_resp = client.post("/tokens", data={"name": "viewer-own-token", "expires_in_days": "", "csrf_token": csrf})
    assert token_resp.status_code == 200
    with engine.begin() as conn:
        owner = conn.execute(text("SELECT user_id FROM api_tokens WHERE name='viewer-own-token'")).scalar_one()
    assert owner == viewer_id

    with engine.begin() as conn:
        status_after = conn.execute(text("SELECT lifecycle_status FROM findings WHERE id=:i"), {"i": finding_id}).scalar_one()
        secret_status_after = conn.execute(text("SELECT lifecycle_status FROM secret_findings WHERE id=:i"), {"i": secret_id}).scalar_one()
    assert status_after == "OPEN"
    assert secret_status_after == "OPEN"

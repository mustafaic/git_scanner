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
    from core.models import AuditLog, Finding, Repository, ScanRun, ScanTrigger, SecretFinding, User


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
            "api_tokens", "audit_log", "sessions", "users", "repositories", "scan_triggers", "scan_runs",
            "notification_log", "settings", "repo_owners",
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
        ("post", "/users", {"username": "sneaky", "password": "DoesntMatter!123", "csrf_token": csrf}),
        ("post", "/users/1/toggle-active", {"csrf_token": csrf}),
        ("post", "/users/1/reset-password", {"new_password": "DoesntMatter!123", "csrf_token": csrf}),
        ("post", "/settings/sla", {"kev": "1", "cvss_9": "3", "cvss_7": "14", "cvss_4": "60", "default": "90", "csrf_token": csrf}),
        ("post", "/settings/notifications", {"email_enabled": "true", "recipients": "x@internal", "csrf_token": csrf}),
    ]
    for method, path, data in write_requests:
        resp = getattr(client, method)(path, data=data, follow_redirects=False)
        assert resp.status_code == 403, f"{method.upper()} {path} viewer'a 403 vermeli, {resp.status_code} dondu"

    audit_resp = client.get("/audit-log")
    assert audit_resp.status_code == 403
    users_resp = client.get("/users")
    assert users_resp.status_code == 403
    settings_resp = client.get("/settings")
    assert settings_resp.status_code == 403
    owners_resp = client.get("/owners")
    assert owners_resp.status_code == 403
    owners_import_resp = client.post(
        "/owners/import", files={"file": ("x.csv", b"acme/x,team-a", "text/csv")}, data={"csrf_token": csrf},
    )
    assert owners_import_resp.status_code == 403

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


# --- Stage 4 part 1: A10 kullanici yonetimi (admin-only, viewer-only olusturma) ---

def test_admin_creates_viewer_toggles_active_and_resets_password(client, engine):
    admin_id, secret = _make_admin(engine)
    code = pyotp.TOTP(secret).now()
    _login(client, "admin", ADMIN_PASSWORD, code)
    csrf = _csrf_token(client)

    resp = client.post("/users", data={"username": "newviewer", "password": VIEWER_PASSWORD, "csrf_token": csrf}, follow_redirects=False)
    assert resp.status_code == 303

    with engine.begin() as conn:
        row = conn.execute(text("SELECT id, role, is_active FROM users WHERE username='newviewer'")).one()
    assert row[1] == "viewer"
    assert row[2] is True
    new_user_id = row[0]

    toggle_resp = client.post(f"/users/{new_user_id}/toggle-active", data={"csrf_token": csrf}, follow_redirects=False)
    assert toggle_resp.status_code == 303
    with engine.begin() as conn:
        is_active = conn.execute(text("SELECT is_active FROM users WHERE id=:i"), {"i": new_user_id}).scalar_one()
    assert is_active is False

    # Login testine devam etmeden ONCE tekrar aktif et (disable/enable
    # ayri bir endpoint degil, aynı toggle -- bu testte her ikisini de
    # kapsiyoruz).
    client.post(f"/users/{new_user_id}/toggle-active", data={"csrf_token": csrf}, follow_redirects=False)
    with engine.begin() as conn:
        is_active_again = conn.execute(text("SELECT is_active FROM users WHERE id=:i"), {"i": new_user_id}).scalar_one()
    assert is_active_again is True

    reset_resp = client.post(
        f"/users/{new_user_id}/reset-password", data={"new_password": "AnotherStr0ng!Pw#9", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert reset_resp.status_code == 303

    with engine.begin() as conn:
        actions = [r[0] for r in conn.execute(text("SELECT action FROM audit_log ORDER BY id")).fetchall()]
    assert "user_created" in actions
    assert "user_active_toggled" in actions
    assert "user_password_reset" in actions

    new_client = TestClient(app)
    login_resp = _login(new_client, "newviewer", "AnotherStr0ng!Pw#9")
    assert login_resp.status_code == 303


def test_admin_cannot_disable_own_account(client, engine):
    admin_id, secret = _make_admin(engine)
    code = pyotp.TOTP(secret).now()
    _login(client, "admin", ADMIN_PASSWORD, code)
    csrf = _csrf_token(client)
    resp = client.post(f"/users/{admin_id}/toggle-active", data={"csrf_token": csrf}, follow_redirects=False)
    assert resp.status_code == 400


def test_create_user_rejects_duplicate_username_and_weak_password(client, engine):
    admin_id, secret = _make_admin(engine)
    _make_viewer(engine, username="existing")
    code = pyotp.TOTP(secret).now()
    _login(client, "admin", ADMIN_PASSWORD, code)
    csrf = _csrf_token(client)

    dup_resp = client.post("/users", data={"username": "existing", "password": VIEWER_PASSWORD, "csrf_token": csrf})
    assert dup_resp.status_code == 400

    weak_resp = client.post("/users", data={"username": "newperson", "password": "short", "csrf_token": csrf})
    assert weak_resp.status_code == 400


# --- Stage 4 part 1: A1 aksiyon gruplari + A2 blast radius -----------------

def test_action_groups_group_findings_by_package_and_fix_version(client, engine):
    admin_id, secret = _make_admin(engine)
    from sqlalchemy.orm import sessionmaker

    Session = sessionmaker(bind=engine, future=True)
    with Session() as session:
        session.add_all([
            Repository(github_repo_id=10, full_name="acme/a", owner="acme", name="a", default_branch="main", visibility="private"),
            Repository(github_repo_id=11, full_name="acme/b", owner="acme", name="b", default_branch="main", visibility="private"),
        ])
        session.add_all([
            Finding(
                repo_id=10, lockfile_path="package-lock.json", ecosystem="npm", package_name="lodash",
                version="4.17.15", canonical_vulnerability_id="GHSA-aaa", verification_status="VERIFIED",
                lifecycle_status="OPEN", fix_status="PATCH_AVAILABLE", fix_version="4.17.19",
            ),
            Finding(
                repo_id=11, lockfile_path="package-lock.json", ecosystem="npm", package_name="lodash",
                version="4.17.10", canonical_vulnerability_id="GHSA-bbb", verification_status="VERIFIED",
                lifecycle_status="OPEN", fix_status="PATCH_AVAILABLE", fix_version="4.17.19",
            ),
        ])
        session.commit()

    code = pyotp.TOTP(secret).now()
    _login(client, "admin", ADMIN_PASSWORD, code)
    resp = client.get("/action-groups")
    assert resp.status_code == 200
    assert "lodash" in resp.text
    assert "npm install lodash@4.17.19" in resp.text
    assert "2" in resp.text  # repo_count/finding_count


def test_action_groups_shows_warning_instead_of_hint_for_unsafe_package_name(client, engine):
    admin_id, secret = _make_admin(engine)
    from sqlalchemy.orm import sessionmaker

    Session = sessionmaker(bind=engine, future=True)
    with Session() as session:
        session.add(Repository(github_repo_id=12, full_name="acme/c", owner="acme", name="c", default_branch="main", visibility="private"))
        session.add(Finding(
            repo_id=12, lockfile_path="package-lock.json", ecosystem="npm", package_name="lodash; rm -rf /",
            version="4.17.15", canonical_vulnerability_id="GHSA-ccc", verification_status="VERIFIED",
            lifecycle_status="OPEN", fix_status="PATCH_AVAILABLE", fix_version="4.17.19",
        ))
        session.commit()

    code = pyotp.TOTP(secret).now()
    _login(client, "admin", ADMIN_PASSWORD, code)
    resp = client.get("/action-groups")
    assert resp.status_code == 200
    assert "rm -rf" not in resp.text or "doğrulanamadı" in resp.text
    assert "doğrulanamadı" in resp.text


def test_blast_radius_search_finds_affected_repos(client, engine):
    admin_id, secret = _make_admin(engine)
    from sqlalchemy.orm import sessionmaker

    Session = sessionmaker(bind=engine, future=True)
    with Session() as session:
        session.add(Repository(github_repo_id=13, full_name="acme/blast", owner="acme", name="blast", default_branch="main", visibility="private"))
        session.add(Finding(
            repo_id=13, lockfile_path="package-lock.json", ecosystem="npm", package_name="left-pad",
            version="1.0.0", canonical_vulnerability_id="GHSA-blast-1", verification_status="VERIFIED",
            lifecycle_status="OPEN",
        ))
        session.commit()

    code = pyotp.TOTP(secret).now()
    _login(client, "admin", ADMIN_PASSWORD, code)
    resp = client.get("/blast-radius", params={"q": "left-pad"})
    assert resp.status_code == 200
    assert "acme/blast" in resp.text

    empty_resp = client.get("/blast-radius", params={"q": "no-such-package-xyz"})
    assert "Eşleşen bulgu yok" in empty_resp.text


# --- Stage 4 part 1: A3 coverage ------------------------------------------

def test_coverage_page_surfaces_lockfile_less_partial_and_lagging_signals(client, engine):
    admin_id, secret = _make_admin(engine)
    from sqlalchemy.orm import sessionmaker

    Session = sessionmaker(bind=engine, future=True)
    with Session() as session:
        session.add_all([
            Repository(github_repo_id=20, full_name="acme/no-lockfile", owner="acme", name="no-lockfile", default_branch="main", visibility="private"),
            Repository(github_repo_id=21, full_name="acme/partial-scan", owner="acme", name="partial-scan", default_branch="main", visibility="private"),
            Repository(github_repo_id=22, full_name="acme/never-scanned", owner="acme", name="never-scanned", default_branch="main", visibility="private"),
        ])
        session.add_all([
            ScanRun(run_type="extraction", repo_id=20, status="success", details={"files": []}),
            ScanRun(run_type="extraction", repo_id=21, status="partial", error="blob_fetch_failed", details={"files": [{"path": "x", "status": "blob_fetch_failed"}]}),
            ScanTrigger(repo_id=20, source="manual"),
        ])
        session.commit()

    import datetime as dt

    with engine.begin() as conn:
        conn.execute(
            text("UPDATE scan_triggers SET created_at = :t WHERE repo_id = 20"),
            {"t": dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=2)},
        )

    code = pyotp.TOTP(secret).now()
    _login(client, "admin", ADMIN_PASSWORD, code)
    resp = client.get("/coverage")
    assert resp.status_code == 200
    assert "acme/no-lockfile" in resp.text
    assert "acme/partial-scan" in resp.text
    assert "acme/never-scanned" in resp.text


# --- Stage 4 part 2: A9 CSV/JSON export -------------------------------------

def test_findings_export_csv_and_json_contain_expected_data(client, engine):
    admin_id, secret = _make_admin(engine)
    from sqlalchemy.orm import sessionmaker

    Session = sessionmaker(bind=engine, future=True)
    with Session() as session:
        session.add(Repository(github_repo_id=30, full_name="acme/export-check", owner="acme", name="export-check", default_branch="main", visibility="private"))
        session.add(Finding(
            repo_id=30, lockfile_path="package-lock.json", ecosystem="npm", package_name="lodash",
            version="4.17.15", canonical_vulnerability_id="GHSA-export-1", verification_status="VERIFIED",
            lifecycle_status="OPEN",
        ))
        session.commit()

    code = pyotp.TOTP(secret).now()
    _login(client, "admin", ADMIN_PASSWORD, code)

    csv_resp = client.get("/findings/export.csv")
    assert csv_resp.status_code == 200
    assert csv_resp.headers["content-type"].startswith("text/csv")
    assert "attachment" in csv_resp.headers["content-disposition"]
    assert "acme/export-check" in csv_resp.text
    assert "GHSA-export-1" in csv_resp.text

    json_resp = client.get("/findings/export.json")
    assert json_resp.status_code == 200
    body = json_resp.json()
    assert any(row["canonical_vulnerability_id"] == "GHSA-export-1" for row in body)


def test_findings_detail_route_still_works_after_adding_export_routes(client, engine):
    """Route siralama regresyon testi: /findings/export.csv eklenmesi
    /findings/{finding_id}'i BOZMAMALI (bkz. app/main.py router sira notu)."""
    _, secret = _make_admin(engine)
    from sqlalchemy.orm import sessionmaker

    Session = sessionmaker(bind=engine, future=True)
    with Session() as session:
        session.add(Repository(github_repo_id=31, full_name="acme/route-order", owner="acme", name="route-order", default_branch="main", visibility="private"))
        finding = Finding(
            repo_id=31, lockfile_path="package-lock.json", ecosystem="npm", package_name="lodash",
            version="4.17.15", canonical_vulnerability_id="GHSA-route-1", verification_status="VERIFIED",
            lifecycle_status="OPEN",
        )
        session.add(finding)
        session.commit()
        finding_id = finding.id

    code = pyotp.TOTP(secret).now()
    _login(client, "admin", ADMIN_PASSWORD, code)
    resp = client.get(f"/findings/{finding_id}")
    assert resp.status_code == 200
    assert "GHSA-route-1" in resp.text


def test_secrets_export_csv_never_contains_raw_secret(client, engine):
    admin_id, secret = _make_admin(engine)
    from sqlalchemy.orm import sessionmaker

    Session = sessionmaker(bind=engine, future=True)
    with Session() as session:
        session.add(Repository(github_repo_id=32, full_name="acme/secret-export", owner="acme", name="secret-export", default_branch="main", visibility="private"))
        session.add(SecretFinding(
            repo_id=32, rule_id="github-pat", file_path="settings.py",
            custom_fingerprint="fp-export-check", secret_content_hash="hash-export-check", lifecycle_status="OPEN",
        ))
        session.commit()

    code = pyotp.TOTP(secret).now()
    _login(client, "admin", ADMIN_PASSWORD, code)
    resp = client.get("/secrets/export.csv")
    assert resp.status_code == 200
    assert "acme/secret-export" in resp.text
    assert "hash-export-check" not in resp.text  # hash SUTUNU export'ta YOK (ihtiyac yok)


def test_audit_log_export_is_admin_only(client, engine):
    _make_viewer(engine)
    _login(client, "viewer", VIEWER_PASSWORD)
    resp = client.get("/audit-log/export.csv")
    assert resp.status_code == 403


# --- Stage 4 part 3: A10 settings (SLA + notifications) + A8 SLA display ---

def test_settings_page_shows_defaults_when_unset(client, engine):
    _, secret = _make_admin(engine)
    code = pyotp.TOTP(secret).now()
    _login(client, "admin", ADMIN_PASSWORD, code)
    resp = client.get("/settings")
    assert resp.status_code == 200
    assert 'value="1"' in resp.text  # kev varsayilani


def test_update_sla_settings_persists_and_is_audited(client, engine):
    admin_id, secret = _make_admin(engine)
    code = pyotp.TOTP(secret).now()
    _login(client, "admin", ADMIN_PASSWORD, code)
    csrf = _csrf_token(client)

    resp = client.post(
        "/settings/sla", data={"kev": "2", "cvss_9": "5", "cvss_7": "20", "cvss_4": "70", "default": "100", "csrf_token": csrf},
    )
    assert resp.status_code == 200
    assert "kaydedildi" in resp.text

    with engine.begin() as conn:
        value = conn.execute(text("SELECT value FROM settings WHERE key='sla_days'")).scalar_one()
        action = conn.execute(text("SELECT action FROM audit_log WHERE action='settings_sla_updated'")).scalar_one()
    assert value["kev"] == 2
    assert action == "settings_sla_updated"


def test_update_sla_settings_rejects_non_positive_values(client, engine):
    _, secret = _make_admin(engine)
    code = pyotp.TOTP(secret).now()
    _login(client, "admin", ADMIN_PASSWORD, code)
    csrf = _csrf_token(client)
    resp = client.post(
        "/settings/sla", data={"kev": "0", "cvss_9": "5", "cvss_7": "20", "cvss_4": "70", "default": "100", "csrf_token": csrf},
    )
    assert resp.status_code == 400


def test_update_notification_settings_persists_recipients_and_is_audited(client, engine):
    _, secret = _make_admin(engine)
    code = pyotp.TOTP(secret).now()
    _login(client, "admin", ADMIN_PASSWORD, code)
    csrf = _csrf_token(client)

    resp = client.post(
        "/settings/notifications",
        data={"email_enabled": "true", "recipients": "a@internal, b@internal\nc@internal", "csrf_token": csrf},
    )
    assert resp.status_code == 200

    with engine.begin() as conn:
        value = conn.execute(text("SELECT value FROM settings WHERE key='notifications'")).scalar_one()
        action = conn.execute(text("SELECT action FROM audit_log WHERE action='settings_notifications_updated'")).scalar_one()
    assert value["email_enabled"] is True
    assert set(value["recipients"]) == {"a@internal", "b@internal", "c@internal"}
    assert action == "settings_notifications_updated"


def test_findings_list_shows_overdue_sla_badge_with_custom_settings(client, engine):
    """Kritik senaryo: SLA 1 gune ayarlanmis + bulgu 10 gun once gorulmus
    -> 'gecikmis' rozeti gorunmeli (master_prompt.md 6 A8 'gecikenler listesi')."""
    admin_id, secret = _make_admin(engine)
    from sqlalchemy.orm import sessionmaker

    Session = sessionmaker(bind=engine, future=True)
    with Session() as session:
        session.add(Repository(github_repo_id=40, full_name="acme/sla-check", owner="acme", name="sla-check", default_branch="main", visibility="private"))
        finding = Finding(
            repo_id=40, lockfile_path="package-lock.json", ecosystem="npm", package_name="lodash",
            version="4.17.15", canonical_vulnerability_id="GHSA-sla-1", verification_status="VERIFIED",
            lifecycle_status="OPEN", severity_cvss_score=9.5,
        )
        session.add(finding)
        session.commit()
        finding_id = finding.id

    import datetime as dt

    with engine.begin() as conn:
        conn.execute(
            text("UPDATE findings SET first_seen_at = :t WHERE id=:i"),
            {"t": dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=10), "i": finding_id},
        )

    code = pyotp.TOTP(secret).now()
    _login(client, "admin", ADMIN_PASSWORD, code)
    csrf = _csrf_token(client)
    # SLA'yi KEV disinda herkes icin 1 gune cekiyoruz -- CVSS 9.5 "cvss_9" dilimine girer.
    client.post("/settings/sla", data={"kev": "1", "cvss_9": "1", "cvss_7": "14", "cvss_4": "60", "default": "90", "csrf_token": csrf})

    resp = client.get("/findings")
    assert resp.status_code == 200
    assert "gün gecikmiş" in resp.text

    detail_resp = client.get(f"/findings/{finding_id}")
    assert "gün gecikmiş" in detail_resp.text


# --- Stage 4 part 4: A5 sahip yonlendirme (CSV import) ----------------------

def test_owners_csv_import_maps_known_repo_and_flags_unknown(client, engine):
    _, secret = _make_admin(engine)
    from sqlalchemy.orm import sessionmaker

    Session = sessionmaker(bind=engine, future=True)
    with Session() as session:
        session.add(Repository(github_repo_id=50, full_name="acme/owned-repo", owner="acme", name="owned-repo", default_branch="main", visibility="private"))
        session.commit()

    code = pyotp.TOTP(secret).now()
    _login(client, "admin", ADMIN_PASSWORD, code)
    csrf = _csrf_token(client)

    csv_content = b"acme/owned-repo,team-platform\nacme/does-not-exist,team-ghost\n"
    resp = client.post("/owners/import", files={"file": ("owners.csv", csv_content, "text/csv")}, data={"csrf_token": csrf})
    assert resp.status_code == 200
    assert "İçe aktarıldı: 1" in resp.text
    assert "bilinmeyen repo: 1" in resp.text

    with engine.begin() as conn:
        owner = conn.execute(text("SELECT owner_identifier, source FROM repo_owners WHERE repo_id=50")).one()
        action = conn.execute(text("SELECT action FROM audit_log WHERE action='owners_csv_imported'")).scalar_one()
    assert owner == ("team-platform", "csv")
    assert action == "owners_csv_imported"


def test_owners_csv_reimport_is_idempotent_no_duplicate_rows(client, engine):
    _, secret = _make_admin(engine)
    from sqlalchemy.orm import sessionmaker

    Session = sessionmaker(bind=engine, future=True)
    with Session() as session:
        session.add(Repository(github_repo_id=51, full_name="acme/dup-check", owner="acme", name="dup-check", default_branch="main", visibility="private"))
        session.commit()

    code = pyotp.TOTP(secret).now()
    _login(client, "admin", ADMIN_PASSWORD, code)
    csrf = _csrf_token(client)
    csv_content = b"acme/dup-check,team-platform\n"

    client.post("/owners/import", files={"file": ("owners.csv", csv_content, "text/csv")}, data={"csrf_token": csrf})
    resp2 = client.post("/owners/import", files={"file": ("owners.csv", csv_content, "text/csv")}, data={"csrf_token": csrf})
    assert "zaten vardı: 1" in resp2.text

    with engine.begin() as conn:
        count = conn.execute(text("SELECT count(*) FROM repo_owners WHERE repo_id=51")).scalar_one()
    assert count == 1


def test_coverage_shows_unowned_repo_until_owner_imported(client, engine):
    """NOT: repo icin basarili bir extraction ScanRun'i de eklenir --
    aksi halde repo ayrica 'hic taranmamis' bolumunde de gorunur ve test
    sadece 'sahipsiz' sinyalini izole edemez."""
    _, secret = _make_admin(engine)
    from sqlalchemy.orm import sessionmaker

    Session = sessionmaker(bind=engine, future=True)
    with Session() as session:
        session.add(Repository(github_repo_id=52, full_name="acme/needs-owner", owner="acme", name="needs-owner", default_branch="main", visibility="private"))
        session.add(ScanRun(
            run_type="extraction", repo_id=52, status="success",
            details={"files": [{"path": "package-lock.json", "status": "parsed"}]},
        ))
        session.commit()

    code = pyotp.TOTP(secret).now()
    _login(client, "admin", ADMIN_PASSWORD, code)
    csrf = _csrf_token(client)

    resp = client.get("/coverage")
    assert "acme/needs-owner" in resp.text

    client.post(
        "/owners/import", files={"file": ("owners.csv", b"acme/needs-owner,team-platform\n", "text/csv")},
        data={"csrf_token": csrf},
    )
    resp2 = client.get("/coverage")
    assert "acme/needs-owner" not in resp2.text


def test_blast_radius_shows_owner_column(client, engine):
    _, secret = _make_admin(engine)
    from sqlalchemy.orm import sessionmaker

    Session = sessionmaker(bind=engine, future=True)
    with Session() as session:
        session.add(Repository(github_repo_id=53, full_name="acme/owner-blast", owner="acme", name="owner-blast", default_branch="main", visibility="private"))
        session.add(Finding(
            repo_id=53, lockfile_path="package-lock.json", ecosystem="npm", package_name="left-pad-owner-test",
            version="1.0.0", canonical_vulnerability_id="GHSA-owner-1", verification_status="VERIFIED",
            lifecycle_status="OPEN",
        ))
        session.commit()

    code = pyotp.TOTP(secret).now()
    _login(client, "admin", ADMIN_PASSWORD, code)
    csrf = _csrf_token(client)
    client.post(
        "/owners/import", files={"file": ("owners.csv", b"acme/owner-blast,team-platform\n", "text/csv")},
        data={"csrf_token": csrf},
    )

    resp = client.get("/blast-radius", params={"q": "left-pad-owner-test"})
    assert resp.status_code == 200
    assert "team-platform" in resp.text

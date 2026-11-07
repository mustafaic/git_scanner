#!/usr/bin/env python3
"""GitHub org repository inventory tool (Aşama 0).

Bir GitHub organizasyonundaki tüm repoları listeler ve Aşama 1+ planlaması
için gereken sinyalleri toplar: visibility, archived/fork durumu, diller,
lockfile/manifest varlığı (ekosistem bazında), Dockerfile/compose varlığı,
CODEOWNERS varlığı, Dependabot alert erişimi (yalnızca HTTP durum kodu —
bulgu içeriği okunmaz), son 30/90 günde commit alıp almadığı (hızlı yoklama
bütçesini planlamak için) ve kaba (tekilleştirilmemiş) bileşen sayısı tahmini.

Bu script sıfır üçüncü-parti bağımlılıkla çalışır (yalnızca stdlib), çünkü
Aşama 0'da henüz bağımlılık pinleme/Docker iskeleti kurulu değildir.

Güvenlik notları:
- Token SADECE ortam değişkeninden okunur (GITHUB_TOKEN). Komut satırı
  argümanı olarak kabul edilmez, hiçbir log/print satırına yazılmaz.
- Üretilen inventory.csv ve inventory_summary.json şirkete ait repo/paket
  adları içerir: bunlar asla git'e commit edilmez, dışarı gönderilmez
  (.gitignore'da hariç tutulmuştur). Bu dosyaları yalnızca iç ağda tut.
- Bileşen sayısı tahmini KABA bir üst sınırdır (tekilleştirme yapılmaz,
  aynı paket@sürüm birden fazla repoda tekrar sayılır). Gerçek benzersiz
  sayı Aşama 2 Hat B'de offline eşleştirme motoruyla ölçülecektir.

Kullanım:
    export GITHUB_TOKEN=...   # salt-okunur bir token/App installation token
    python tools/inventory.py --org <org-adi> \\
        [--api-base-url https://api.github.com] \\
        [--out inventory.csv] [--summary-out inventory_summary.json] \\
        [--no-component-estimate] [--verbose]

GitHub Enterprise Server (GHES) için --api-base-url genelde
https://<ghes-host>/api/v3 biçimindedir (bkz. docs/VERIFIED_FACTS.md).
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

LOG = logging.getLogger("inventory")

TOKEN_ENV_VAR = "GITHUB_TOKEN"
DEFAULT_API_BASE_URL = "https://api.github.com"
USER_AGENT = "scanner-platform-inventory/0.1 (+stage0)"

# --- Ekosistem tespiti --------------------------------------------------

# basename -> ekosistem; gerçek bir lockfile (çözülmüş tam sürüm) var demektir.
# KAYNAK (bkz. docs/VERIFIED_FACTS.md): OSV-Scanner'ın resmi desteklenen
# lockfile listesi (google.github.io/osv-scanner/supported-languages-and-lockfiles/,
# erişim 2026-11-08). Go için OSV-Scanner go.sum DEĞİL go.mod'u okur (Go
# modüllerinde go.mod zaten tam/pinli sürüm içerir, go.sum salt checksum'dır)
# -> master_prompt.md'nin ilk taslağındaki "go.sum" varsayımı burada DÜZELTİLDİ.
LOCKFILE_PATTERNS: Dict[str, str] = {
    "package-lock.json": "npm",
    "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm",
    "bun.lock": "bun",
    "poetry.lock": "poetry",
    "pdm.lock": "pdm",
    "uv.lock": "uv",
    "pylock.toml": "pylock",
    "Pipfile.lock": "pipenv",
    "Cargo.lock": "cargo",
    "composer.lock": "composer",
    "Gemfile.lock": "bundler",
    "gems.locked": "bundler",
    "go.mod": "go",
    "packages.lock.json": "nuget",
    "packages.config": "nuget",
    "gradle.lockfile": "gradle",
    "buildscript-gradle.lockfile": "gradle",
}

# basename -> ekosistem; manifest var ama GÜVENİLİR ŞEKİLDE çözülmüş tam
# sürüm garantisi yok (aralık bazlı olabilir, ya da resolver şirket dışı bir
# servise bağımlı) -> master_prompt.md 4.2: asla Verified olamaz,
# UNVERIFIED_NO_LOCKFILE. pom.xml bilerek burada: OSV-Scanner pom.xml'i
# doğrudan okuyabiliyor (bkz. VERIFIED_FACTS) ama Maven sürüm aralıkları/
# property'leri içerebilir ve güvenilir tam-sürüm resolution'ı Aşama 0b
# fixture testiyle doğrulanana kadar varsayım; bu yüzden temkinli taraf
# seçildi (ASSUMPTIONS.md'de not edilir, kullanıcı onayı gerekir).
MANIFEST_ONLY_PATTERNS: Dict[str, str] = {
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "Gemfile": "bundler",
    "Pipfile": "pipenv",
    "composer.json": "composer",
    "package.json": "npm",
}

DOCKERFILE_BASENAMES = {"dockerfile"}
COMPOSE_BASENAMES = {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
CODEOWNERS_PATHS = {"CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"}

# Contents API ~1MB üstü dosyalarda 200 dönmeyebilir (Blobs API gerekir);
# bu script için bu durumda sadece tahmini atlıyoruz (bkz. docs/ASSUMPTIONS.md).
MAX_REASONABLE_LOCKFILE_BYTES = 5 * 1024 * 1024


@dataclass
class ClassifiedPaths:
    lockfiles: Dict[str, List[str]] = field(default_factory=dict)
    manifest_only: Dict[str, List[str]] = field(default_factory=dict)
    has_dockerfile: bool = False
    has_compose: bool = False
    has_codeowners: bool = False


def classify_paths(paths: List[str]) -> ClassifiedPaths:
    """Bir repo ağacındaki (tree) dosya yollarını ekosistem/sinyal olarak sınıflar.

    Saf fonksiyondur (ağ çağrısı yapmaz) -> birim testlenebilir.
    """
    result = ClassifiedPaths()
    for path in paths:
        basename = path.rsplit("/", 1)[-1]
        basename_lower = basename.lower()

        if basename in LOCKFILE_PATTERNS:
            eco = LOCKFILE_PATTERNS[basename]
            result.lockfiles.setdefault(eco, []).append(path)
        elif basename.startswith("requirements") and basename_lower.endswith(".txt"):
            # requirements*.txt: lockfile değildir (aralık bazlı olabilir),
            # çözülmüş tam sürüm garantisi yok -> manifest_only.
            result.manifest_only.setdefault("pip", []).append(path)
        elif basename.endswith(".csproj"):
            result.manifest_only.setdefault("nuget", []).append(path)
        elif basename in MANIFEST_ONLY_PATTERNS:
            eco = MANIFEST_ONLY_PATTERNS[basename]
            result.manifest_only.setdefault(eco, []).append(path)

        if basename_lower in DOCKERFILE_BASENAMES or basename_lower.startswith("dockerfile"):
            result.has_dockerfile = True
        if basename_lower in COMPOSE_BASENAMES:
            result.has_compose = True
        if path in CODEOWNERS_PATHS or basename == "CODEOWNERS":
            result.has_codeowners = True

    return result


# --- Kaba bileşen sayısı tahmini (tekilleştirme YOK, üst sınır) --------

def estimate_npm_lock_components(content: bytes) -> Optional[int]:
    try:
        data = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    packages = data.get("packages")
    if isinstance(packages, dict):
        # lockfileVersion >= 2: kök "" anahtarı projenin kendisidir, sayma.
        return len([k for k in packages.keys() if k != ""])
    dependencies = data.get("dependencies")
    if isinstance(dependencies, dict):
        count = 0

        def walk(deps: Dict[str, Any]) -> None:
            nonlocal count
            for info in deps.values():
                count += 1
                if isinstance(info, dict) and isinstance(info.get("dependencies"), dict):
                    walk(info["dependencies"])

        walk(dependencies)
        return count
    return None


def estimate_yarn_lock_components(content: bytes) -> Optional[int]:
    try:
        text = content.decode("utf-8", errors="ignore")
    except Exception:
        return None
    count = 0
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        if not line[0].isspace() and line.rstrip().endswith(":"):
            count += 1
    return count


def estimate_toml_double_bracket_components(section: str) -> Callable[[bytes], Optional[int]]:
    def _estimate(content: bytes) -> Optional[int]:
        try:
            text = content.decode("utf-8", errors="ignore")
        except Exception:
            return None
        return text.count(section)

    return _estimate


def estimate_pipfile_lock_components(content: bytes) -> Optional[int]:
    try:
        data = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return len(data.get("default", {}) or {}) + len(data.get("develop", {}) or {})


def estimate_composer_lock_components(content: bytes) -> Optional[int]:
    try:
        data = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return len(data.get("packages", []) or []) + len(data.get("packages-dev", []) or [])


def estimate_gemfile_lock_components(content: bytes) -> Optional[int]:
    try:
        text = content.decode("utf-8", errors="ignore")
    except Exception:
        return None
    count = 0
    in_specs = False
    for line in text.splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if not in_specs:
            continue
        if line.startswith("    ") and not line.startswith("     ") and line.strip():
            count += 1
        elif line.strip() and not line.startswith(" "):
            in_specs = False
    return count


def estimate_go_mod_components(content: bytes) -> Optional[int]:
    """go.mod icindeki require direktiflerini sayar (go.sum degil -> bkz. VERIFIED_FACTS.md).

    Go modullerinde go.mod'daki surum ifadeleri zaten tam/pinli oldugu icin
    (semver araligi degil) bu dosya lockfile-esdeger kabul edilir.
    """
    try:
        text = content.decode("utf-8", errors="ignore")
    except Exception:
        return None
    count = 0
    in_require_block = False
    for raw_line in text.splitlines():
        line = raw_line.split("//", 1)[0].strip()
        if not line:
            continue
        if line.startswith("require") and line.endswith("("):
            in_require_block = True
            continue
        if in_require_block:
            if line == ")":
                in_require_block = False
                continue
            if len(line.split()) >= 2:
                count += 1
            continue
        if line.startswith("require ") and len(line.split()) >= 3:
            count += 1
    return count


def estimate_packages_lock_json_components(content: bytes) -> Optional[int]:
    try:
        data = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    deps = data.get("dependencies")
    if not isinstance(deps, dict):
        return None
    names: set = set()
    for framework_deps in deps.values():
        if isinstance(framework_deps, dict):
            names.update(framework_deps.keys())
    return len(names) if names else None


def estimate_gradle_lockfile_components(content: bytes) -> Optional[int]:
    try:
        text = content.decode("utf-8", errors="ignore")
    except Exception:
        return None
    count = 0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("empty="):
            continue
        if ":" in line and "=" in line:
            count += 1
    return count


# pnpm-lock.yaml kasıtlı olarak yok: stdlib'de YAML parser yok, Aşama 0'da
# ek bağımlılık eklemiyoruz (kural 11). docs/ASSUMPTIONS.md'de not edilir.
ESTIMATORS: Dict[str, Callable[[bytes], Optional[int]]] = {
    "npm": estimate_npm_lock_components,
    "yarn": estimate_yarn_lock_components,
    "poetry": estimate_toml_double_bracket_components("[[package]]"),
    "cargo": estimate_toml_double_bracket_components("[[package]]"),
    "pipenv": estimate_pipfile_lock_components,
    "composer": estimate_composer_lock_components,
    "bundler": estimate_gemfile_lock_components,
    "go": estimate_go_mod_components,
    "nuget": estimate_packages_lock_json_components,
    "gradle": estimate_gradle_lockfile_components,
}


# --- GitHub API istemcisi ------------------------------------------------

class GitHubClient:
    """Rate-limit ve ikincil (abuse) limit farkındalıklı minimal REST istemcisi.

    Token yalnızca Authorization header'ında taşınır; hiçbir yerde loglanmaz.
    """

    def __init__(self, base_url: str, token: str, timeout: float = 30.0) -> None:
        self.base_url = base_url.rstrip("/")
        self._token = token
        self.timeout = timeout

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": USER_AGENT,
        }

    @staticmethod
    def rate_limit_wait_seconds(headers: Dict[str, str], now: Optional[float] = None) -> float:
        """Saf fonksiyon: header'lardan ne kadar beklenmesi gerektiğini hesaplar."""
        now = time.time() if now is None else now
        retry_after = headers.get("Retry-After")
        if retry_after is not None:
            try:
                return float(retry_after) + 1.0
            except ValueError:
                pass
        reset = headers.get("X-RateLimit-Reset")
        if reset is not None:
            try:
                return max(int(reset) - now, 1.0) + 1.0
            except ValueError:
                pass
        return 60.0

    @staticmethod
    def is_rate_limited(status: int, headers: Dict[str, str]) -> bool:
        if status == 429:
            return True
        if status == 403 and headers.get("X-RateLimit-Remaining") == "0":
            return True
        if status == 403 and "Retry-After" in headers:
            return True
        return False

    def request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        max_retries: int = 5,
    ) -> Tuple[int, Any, Dict[str, str]]:
        url = self.base_url + path
        if params:
            query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
            if query:
                url = f"{url}?{query}"

        attempt = 0
        while True:
            attempt += 1
            req = urllib.request.Request(url, headers=self._headers(), method=method)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    status = resp.status
                    headers = {k: v for k, v in resp.headers.items()}
                    body = resp.read()
            except urllib.error.HTTPError as exc:
                status = exc.code
                headers = {k: v for k, v in exc.headers.items()} if exc.headers else {}
                body = exc.read() if hasattr(exc, "read") else b""
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                if attempt >= max_retries:
                    raise
                sleep_s = min(2 ** attempt, 60)
                LOG.warning("Ag hatasi (%s), %ss sonra tekrar denenecek (%d/%d)", exc, sleep_s, attempt, max_retries)
                time.sleep(sleep_s)
                continue

            if self.is_rate_limited(status, headers):
                if attempt >= max_retries:
                    raise RuntimeError(f"GitHub API rate limit asildi: {path}")
                wait_s = self.rate_limit_wait_seconds(headers)
                LOG.warning("Rate limit, %.0fs sonra tekrar denenecek (%d/%d): %s", wait_s, attempt, max_retries, path)
                time.sleep(wait_s)
                continue

            if status >= 500 and attempt < max_retries:
                sleep_s = min(2 ** attempt, 60)
                LOG.warning("Sunucu hatasi %s, %ss sonra tekrar denenecek: %s", status, sleep_s, path)
                time.sleep(sleep_s)
                continue

            parsed: Any = None
            if body:
                try:
                    parsed = json.loads(body.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    parsed = body
            return status, parsed, headers

    def paginate(self, path: str, params: Optional[Dict[str, Any]] = None) -> List[Any]:
        params = dict(params or {})
        per_page = int(params.setdefault("per_page", 100))
        page = 1
        items: List[Any] = []
        while True:
            params["page"] = page
            status, data, _headers = self.request("GET", path, params)
            if status != 200:
                raise RuntimeError(f"GitHub API hatasi {status}: {path} -> {data!r}")
            if not isinstance(data, list):
                raise RuntimeError(f"Liste beklenirken {type(data)} alindi: {path}")
            items.extend(data)
            if len(data) < per_page:
                break
            page += 1
        return items


def list_org_repos(client: GitHubClient, org: str) -> List[Dict[str, Any]]:
    return client.paginate(f"/orgs/{org}/repos", {"type": "all"})


def get_languages(client: GitHubClient, owner: str, repo: str) -> Dict[str, int]:
    status, data, _ = client.request("GET", f"/repos/{owner}/{repo}/languages")
    if status != 200 or not isinstance(data, dict):
        return {}
    return data


@dataclass
class TreeBlobEntry:
    path: str
    sha: str


def get_default_branch_tree(
    client: GitHubClient, owner: str, repo: str, default_branch: str
) -> Tuple[List[TreeBlobEntry], bool, Optional[str]]:
    # VERIFIED (docs/VERIFIED_FACTS.md, 2026-11-08): tree_sha parametresi
    # dogrudan bir branch adini kabul eder (once commit/tree SHA'sina cozmek
    # gerekmez). truncated=true, 100.000 girdi veya 7MB toplam boyut
    # asildiginda doner (master_prompt.md 3.2.4'teki guvenli yedek yol budur).
    status, data, _ = client.request(
        "GET", f"/repos/{owner}/{repo}/git/trees/{urllib.parse.quote(default_branch, safe='')}", {"recursive": 1}
    )
    if status != 200 or not isinstance(data, dict):
        return [], False, f"tree_fetch_failed:{status}"
    tree = data.get("tree", [])
    if not isinstance(tree, list):
        return [], False, "tree_fetch_failed:unexpected_shape"
    entries = [
        TreeBlobEntry(path=entry.get("path", ""), sha=entry.get("sha", ""))
        for entry in tree
        if isinstance(entry, dict) and entry.get("type") == "blob"
    ]
    truncated = bool(data.get("truncated"))
    return entries, truncated, None


def check_dependabot_alert_access(client: GitHubClient, owner: str, repo: str) -> int:
    status, _data, _headers = client.request("GET", f"/repos/{owner}/{repo}/dependabot/alerts", {"per_page": 1})
    return status


def had_recent_commits(
    client: GitHubClient, owner: str, repo: str, default_branch: str, days: int
) -> Optional[bool]:
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    status, data, _ = client.request(
        "GET", f"/repos/{owner}/{repo}/commits", {"sha": default_branch, "since": since, "per_page": 1}
    )
    if status != 200 or not isinstance(data, list):
        return None
    return len(data) > 0


def get_blob_content(client: GitHubClient, owner: str, repo: str, blob_sha: str) -> Optional[bytes]:
    """Git Blobs API ile dosya icerigini ceker (Contents API'nin 1MB/100MB
    sinirlarindan bagimsiz, master_prompt.md 3.2.4 ile ayni yaklasim:
    tam klon yerine sadece ilgili blob indirilir)."""
    status, data, _ = client.request("GET", f"/repos/{owner}/{repo}/git/blobs/{blob_sha}")
    if status != 200 or not isinstance(data, dict):
        return None
    if data.get("encoding") != "base64" or not data.get("content"):
        return None
    try:
        return base64.b64decode(data["content"])
    except (ValueError, TypeError):
        return None


# --- Repo kaydi ve ozet ---------------------------------------------------

@dataclass
class RepoRecord:
    name: str
    full_name: str
    visibility: str
    archived: bool
    fork: bool
    default_branch: str
    languages: Dict[str, int]
    lockfiles: Dict[str, List[str]]
    manifest_only: Dict[str, List[str]]
    has_dockerfile: bool
    has_compose: bool
    has_codeowners: bool
    dependabot_alerts_status: Optional[int]
    had_commits_30d: Optional[bool]
    had_commits_90d: Optional[bool]
    tree_truncated: bool
    estimated_components: int
    error: Optional[str] = None


def process_repo(client: GitHubClient, repo_json: Dict[str, Any], estimate_components: bool) -> RepoRecord:
    owner, name = repo_json["full_name"].split("/", 1)
    default_branch = repo_json.get("default_branch") or "main"
    errors: List[str] = []

    languages = get_languages(client, owner, name)

    entries, truncated, tree_err = get_default_branch_tree(client, owner, name, default_branch)
    if tree_err:
        errors.append(tree_err)
    path_to_blob_sha = {e.path: e.sha for e in entries}

    classified = classify_paths([e.path for e in entries])

    dependabot_status: Optional[int] = None
    try:
        dependabot_status = check_dependabot_alert_access(client, owner, name)
    except Exception as exc:  # noqa: BLE001 - bir repo hatasi tum taramayi durdurmamali
        errors.append(f"dependabot_check_failed:{exc}")

    had_30d: Optional[bool] = None
    had_90d: Optional[bool] = None
    try:
        had_30d = had_recent_commits(client, owner, name, default_branch, 30)
        had_90d = had_recent_commits(client, owner, name, default_branch, 90)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"commit_check_failed:{exc}")

    estimated_total = 0
    if estimate_components:
        for eco, eco_paths in classified.lockfiles.items():
            estimator = ESTIMATORS.get(eco)
            if estimator is None:
                continue
            for path in eco_paths:
                blob_sha = path_to_blob_sha.get(path)
                if not blob_sha:
                    continue
                try:
                    content = get_blob_content(client, owner, name, blob_sha)
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"content_fetch_failed:{path}:{exc}")
                    continue
                if not content or len(content) > MAX_REASONABLE_LOCKFILE_BYTES:
                    continue
                count = estimator(content)
                if count:
                    estimated_total += count

    return RepoRecord(
        name=name,
        full_name=repo_json["full_name"],
        visibility=repo_json.get("visibility") or ("private" if repo_json.get("private") else "public"),
        archived=bool(repo_json.get("archived")),
        fork=bool(repo_json.get("fork")),
        default_branch=default_branch,
        languages=languages,
        lockfiles=classified.lockfiles,
        manifest_only=classified.manifest_only,
        has_dockerfile=classified.has_dockerfile,
        has_compose=classified.has_compose,
        has_codeowners=classified.has_codeowners,
        dependabot_alerts_status=dependabot_status,
        had_commits_30d=had_30d,
        had_commits_90d=had_90d,
        tree_truncated=truncated,
        estimated_components=estimated_total,
        error="; ".join(errors) if errors else None,
    )


CSV_FIELDS = [
    "repo", "visibility", "archived", "fork", "default_branch",
    "languages", "lockfile_ecosystems", "lockfile_paths",
    "manifest_only_ecosystems", "has_dockerfile", "has_compose",
    "has_codeowners", "dependabot_alerts_status", "had_commits_30d",
    "had_commits_90d", "tree_truncated", "estimated_component_count_upper_bound",
    "errors",
]


def record_to_row(r: RepoRecord) -> Dict[str, Any]:
    return {
        "repo": r.full_name,
        "visibility": r.visibility,
        "archived": r.archived,
        "fork": r.fork,
        "default_branch": r.default_branch,
        "languages": ";".join(sorted(r.languages.keys())),
        "lockfile_ecosystems": ";".join(sorted(r.lockfiles.keys())),
        "lockfile_paths": ";".join(p for paths in r.lockfiles.values() for p in paths),
        "manifest_only_ecosystems": ";".join(sorted(r.manifest_only.keys())),
        "has_dockerfile": r.has_dockerfile,
        "has_compose": r.has_compose,
        "has_codeowners": r.has_codeowners,
        "dependabot_alerts_status": r.dependabot_alerts_status,
        "had_commits_30d": r.had_commits_30d,
        "had_commits_90d": r.had_commits_90d,
        "tree_truncated": r.tree_truncated,
        "estimated_component_count_upper_bound": r.estimated_components,
        "errors": r.error or "",
    }


def write_csv(records: List[RepoRecord], out_path: str) -> None:
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for r in records:
            writer.writerow(record_to_row(r))


def build_summary(records: List[RepoRecord]) -> Dict[str, Any]:
    total = len(records)
    eco_counts: Dict[str, int] = {}
    manifest_only_counts: Dict[str, int] = {}
    for r in records:
        for eco in r.lockfiles.keys():
            eco_counts[eco] = eco_counts.get(eco, 0) + 1
        for eco in r.manifest_only.keys():
            if eco not in r.lockfiles:
                manifest_only_counts[eco] = manifest_only_counts.get(eco, 0) + 1

    no_lockfile = sum(1 for r in records if not r.lockfiles)

    return {
        "total_repos": total,
        "archived_repos": sum(1 for r in records if r.archived),
        "fork_repos": sum(1 for r in records if r.fork),
        "repos_without_any_lockfile": no_lockfile,
        "repos_without_any_lockfile_ratio": round(no_lockfile / total, 4) if total else None,
        "lockfile_ecosystem_distribution": eco_counts,
        "manifest_only_ecosystem_distribution": manifest_only_counts,
        "repos_with_truncated_tree": sum(1 for r in records if r.tree_truncated),
        "repos_with_errors": sum(1 for r in records if r.error),
        "repos_active_last_30d": sum(1 for r in records if r.had_commits_30d),
        "repos_active_last_90d": sum(1 for r in records if r.had_commits_90d),
        "estimated_component_count_upper_bound_total": sum(r.estimated_components for r in records),
        "note_on_component_estimate": (
            "Bu sayi TEKILLESTIRME ONCESI bir ust sinirdir: ayni paket@surum "
            "birden fazla repoda tekrar tekrar sayilir, pnpm-lock.yaml ve "
            "lockfile'i olmayan ekosistemler (maven/gradle manifest-only) icin "
            "tahmin uretilmez. Gercek benzersiz bilesen sayisi Asama 2 Hat B'de "
            "offline eslestirme motoruyla olculecektir (bkz. master_prompt.md 3.1)."
        ),
    }


# --- CLI ------------------------------------------------------------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--org", required=True, help="GitHub organizasyon login adi")
    parser.add_argument(
        "--api-base-url",
        default=os.environ.get("GITHUB_API_BASE_URL", DEFAULT_API_BASE_URL),
        help="GitHub REST API taban URL'i (GHES icin https://<host>/api/v3)",
    )
    parser.add_argument("--out", default="inventory.csv", help="CSV cikis yolu")
    parser.add_argument("--summary-out", default="inventory_summary.json", help="Ozet JSON cikis yolu")
    parser.add_argument(
        "--no-component-estimate",
        action="store_true",
        help="Kaba bilesen sayisi tahminini atla (daha az API cagrisi)",
    )
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )

    token = os.environ.get(TOKEN_ENV_VAR)
    if not token:
        LOG.error(
            "%s ortam degiskeni ayarli degil. Token'i KOMUT SATIRINA VERME, "
            "sadece ortam degiskeni olarak ayarla.",
            TOKEN_ENV_VAR,
        )
        return 2

    client = GitHubClient(args.api_base_url, token)

    LOG.info("Org repo listesi cekiliyor: %s (%s)", args.org, args.api_base_url)
    try:
        repos_json = list_org_repos(client, args.org)
    except Exception as exc:  # noqa: BLE001
        LOG.error("Repo listesi alinamadi: %s", exc)
        return 1
    LOG.info("%d repo bulundu.", len(repos_json))

    records: List[RepoRecord] = []
    for idx, repo_json in enumerate(repos_json, start=1):
        full_name = repo_json.get("full_name", "?")
        LOG.info("[%d/%d] %s isleniyor", idx, len(repos_json), full_name)
        try:
            record = process_repo(client, repo_json, estimate_components=not args.no_component_estimate)
        except Exception as exc:  # noqa: BLE001
            LOG.warning("Repo %s tamamen islenemedi, hata kaydiyla devam: %s", full_name, exc)
            record = RepoRecord(
                name=repo_json.get("name", "?"),
                full_name=full_name,
                visibility=repo_json.get("visibility", "unknown"),
                archived=bool(repo_json.get("archived")),
                fork=bool(repo_json.get("fork")),
                default_branch=repo_json.get("default_branch", "?"),
                languages={},
                lockfiles={},
                manifest_only={},
                has_dockerfile=False,
                has_compose=False,
                has_codeowners=False,
                dependabot_alerts_status=None,
                had_commits_30d=None,
                had_commits_90d=None,
                tree_truncated=False,
                estimated_components=0,
                error=f"process_failed:{exc}",
            )
        records.append(record)

    write_csv(records, args.out)
    summary = build_summary(records)
    with open(args.summary_out, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    LOG.info("Tamamlandi. CSV: %s | Ozet: %s", args.out, args.summary_out)
    LOG.info("Ozet (sirket disina GONDERME, sadece ic kullanim): %s", json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

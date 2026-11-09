"""Hat A bilesen cikarma: lockfile icerigini PURL/ekosistem/ad/surum/scope
listesine ayristirir (master_prompt.md 3.2.6).

ONEMLI TASARIM NOTU (Asama 2'de ampirik olarak kesfedildi, bkz.
docs/VERIFIED_FACTS.md): OSV-Scanner SADECE zafiyetli paketleri raporlar;
zafiyeti olmayan bir paket icin ciktisi BOMBOS doner (hatta CycloneDX SBOM
export modunda bile). Bu nedenle OSV-Scanner'i Hat A'nin envanter kaynagi
olarak KULLANAMAYIZ -- "bu repoda N bilesen var" bilgisini kaybederiz.
Hat A bu yuzden KENDI (basit, deterministik, surum-araligi KARSILASTIRMASI
YAPMAYAN) lockfile ayristiricisini kullanir; sadece OSV-Scanner'in (Hat B,
adapters/osv_scanner.py) "surum X aralik Y icinde mi" sorusunu cevaplamasina
guveniriz (kural 3: sifirdan surum karsilastirma motoru yazma).

Bu modul tools/inventory.py'deki (Asama 0) kaba tahmin fonksiyonlarinin
yapisal/tam versiyonudur -- ayni ayristirma mantigi, ama sayim yerine
(name, version, scope, relation, purl) kaydi uretir.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

SCOPE_PROD = "prod"
SCOPE_DEV = "dev"
SCOPE_OPTIONAL = "optional"
SCOPE_UNKNOWN = "unknown"

# VERIFIED (2026-11-08, OSV schema: https://ossf.github.io/osv-schema/,
# capital/format onemli): bu string'ler OSV-Scanner'in (Hat B) kendi
# raporladigi `ecosystem` alaniyla AYNI olmali -- Hat A/Hat B korelasyonu
# bu string'lerin birebir eslesmesine dayanir.
ECOSYSTEM_NPM = "npm"
ECOSYSTEM_PYPI = "PyPI"
ECOSYSTEM_GO = "Go"
ECOSYSTEM_CARGO = "crates.io"
ECOSYSTEM_PACKAGIST = "Packagist"
ECOSYSTEM_MAVEN = "Maven"
ECOSYSTEM_NUGET = "NuGet"
ECOSYSTEM_RUBYGEMS = "RubyGems"

RELATION_DIRECT = "direct"
RELATION_TRANSITIVE = "transitive"
RELATION_UNKNOWN = "unknown"


@dataclass(frozen=True)
class ParsedComponent:
    ecosystem: str
    name: str
    version: str
    scope: str = SCOPE_UNKNOWN
    relation: str = RELATION_UNKNOWN
    purl: Optional[str] = None


def _purl(purl_type: str, name: str, version: str, namespace: Optional[str] = None) -> str:
    quoted_name = urllib.parse.quote(name, safe="")
    if namespace:
        quoted_ns = urllib.parse.quote(namespace, safe="")
        return f"pkg:{purl_type}/{quoted_ns}/{quoted_name}@{version}"
    return f"pkg:{purl_type}/{quoted_name}@{version}"


# --- npm: package-lock.json ------------------------------------------------

def parse_npm_lock(content: bytes) -> List[ParsedComponent]:
    try:
        data = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []

    components: List[ParsedComponent] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for pkg_path, info in packages.items():
            if pkg_path == "" or not isinstance(info, dict):
                continue
            name = info.get("name") or pkg_path.rsplit("node_modules/", 1)[-1]
            version = info.get("version")
            if not version:
                continue
            scope = SCOPE_DEV if info.get("dev") else (SCOPE_OPTIONAL if info.get("optional") else SCOPE_PROD)
            relation = RELATION_DIRECT if pkg_path.count("node_modules/") == 1 else RELATION_TRANSITIVE
            components.append(
                ParsedComponent(ECOSYSTEM_NPM, name, version, scope, relation, _purl("npm", name, version))
            )
        return components

    dependencies = data.get("dependencies")
    if isinstance(dependencies, dict):
        def walk(deps: Dict[str, Any], relation: str) -> None:
            for name, info in deps.items():
                if not isinstance(info, dict):
                    continue
                version = info.get("version")
                if not version:
                    continue
                scope = SCOPE_DEV if info.get("dev") else SCOPE_PROD
                components.append(
                    ParsedComponent(ECOSYSTEM_NPM, name, version, scope, relation, _purl("npm", name, version))
                )
                nested = info.get("dependencies")
                if isinstance(nested, dict):
                    walk(nested, RELATION_TRANSITIVE)

        walk(dependencies, RELATION_DIRECT)
    return components


# --- yarn.lock --------------------------------------------------------------

def parse_yarn_lock(content: bytes) -> List[ParsedComponent]:
    try:
        text = content.decode("utf-8", errors="ignore")
    except Exception:
        return []
    components: List[ParsedComponent] = []
    current_names: List[str] = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        if not line[0].isspace() and line.rstrip().endswith(":"):
            header = line.rstrip().rstrip(":")
            specs = [s.strip().strip('"') for s in header.split(",")]
            current_names = [s.split("@")[0] if not s.startswith("@") else "@" + s[1:].split("@")[0] for s in specs]
            continue
        stripped = line.strip()
        if current_names and stripped.startswith("version "):
            version = stripped.split(" ", 1)[1].strip().strip('"')
            for name in current_names:
                if name:
                    components.append(
                        ParsedComponent(ECOSYSTEM_NPM, name, version, SCOPE_UNKNOWN, RELATION_UNKNOWN, _purl("npm", name, version))
                    )
            current_names = []
    return components


# --- poetry.lock / Cargo.lock (TOML [[package]] bloklari) -------------------

def _parse_toml_package_blocks(content: bytes, purl_type: str, ecosystem: str) -> List[ParsedComponent]:
    try:
        text = content.decode("utf-8", errors="ignore")
    except Exception:
        return []
    components: List[ParsedComponent] = []
    name: Optional[str] = None
    version: Optional[str] = None
    in_block = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line == "[[package]]":
            if name and version:
                components.append(ParsedComponent(ecosystem, name, version, SCOPE_UNKNOWN, RELATION_UNKNOWN, _purl(purl_type, name, version)))
            name, version, in_block = None, None, True
            continue
        if in_block and line.startswith("name = "):
            name = line.split("=", 1)[1].strip().strip('"')
        elif in_block and line.startswith("version = "):
            version = line.split("=", 1)[1].strip().strip('"')
    if name and version:
        components.append(ParsedComponent(ecosystem, name, version, SCOPE_UNKNOWN, RELATION_UNKNOWN, _purl(purl_type, name, version)))
    return components


def parse_poetry_lock(content: bytes) -> List[ParsedComponent]:
    return _parse_toml_package_blocks(content, "pypi", ECOSYSTEM_PYPI)


def parse_cargo_lock(content: bytes) -> List[ParsedComponent]:
    return _parse_toml_package_blocks(content, "cargo", ECOSYSTEM_CARGO)


# --- Pipfile.lock -------------------------------------------------------------

def parse_pipfile_lock(content: bytes) -> List[ParsedComponent]:
    try:
        data = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []
    components: List[ParsedComponent] = []
    for section, scope in (("default", SCOPE_PROD), ("develop", SCOPE_DEV)):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for name, info in deps.items():
            if not isinstance(info, dict):
                continue
            version = info.get("version")
            if not version:
                continue
            version = version.lstrip("=")
            components.append(ParsedComponent(ECOSYSTEM_PYPI, name, version, scope, RELATION_UNKNOWN, _purl("pypi", name, version)))
    return components


# --- composer.lock -------------------------------------------------------------

def parse_composer_lock(content: bytes) -> List[ParsedComponent]:
    try:
        data = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []
    components: List[ParsedComponent] = []
    for key, scope in (("packages", SCOPE_PROD), ("packages-dev", SCOPE_DEV)):
        for pkg in data.get(key, []) or []:
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name")
            version = pkg.get("version")
            if not name or not version:
                continue
            version = version.lstrip("v")
            components.append(ParsedComponent(ECOSYSTEM_PACKAGIST, name, version, scope, RELATION_UNKNOWN, _purl("composer", name, version)))
    return components


# --- Gemfile.lock -------------------------------------------------------------

def parse_gemfile_lock(content: bytes) -> List[ParsedComponent]:
    try:
        text = content.decode("utf-8", errors="ignore")
    except Exception:
        return []
    components: List[ParsedComponent] = []
    in_specs = False
    for line in text.splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if not in_specs:
            continue
        if line.startswith("    ") and not line.startswith("     ") and line.strip():
            rest = line.strip()
            if "(" in rest and rest.endswith(")"):
                name, version = rest[:-1].split("(", 1)
                components.append(
                    ParsedComponent(ECOSYSTEM_RUBYGEMS, name.strip(), version.strip(), SCOPE_UNKNOWN, RELATION_DIRECT, _purl("gem", name.strip(), version.strip()))
                )
        elif line.strip() and not line.startswith(" "):
            in_specs = False
    return components


# --- go.mod ---------------------------------------------------------------

def parse_go_mod(content: bytes) -> List[ParsedComponent]:
    try:
        text = content.decode("utf-8", errors="ignore")
    except Exception:
        return []
    components: List[ParsedComponent] = []
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
            parts = line.split()
            if len(parts) >= 2:
                components.append(
                    ParsedComponent(ECOSYSTEM_GO, parts[0], parts[1], SCOPE_PROD, RELATION_DIRECT, _purl("golang", parts[0], parts[1]))
                )
            continue
        if line.startswith("require "):
            parts = line.split()
            if len(parts) >= 3:
                components.append(
                    ParsedComponent(ECOSYSTEM_GO, parts[1], parts[2], SCOPE_PROD, RELATION_DIRECT, _purl("golang", parts[1], parts[2]))
                )
    return components


# --- packages.lock.json (NuGet) ------------------------------------------

def parse_packages_lock_json(content: bytes) -> List[ParsedComponent]:
    try:
        data = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []
    deps = data.get("dependencies")
    if not isinstance(deps, dict):
        return []
    seen: Dict[str, str] = {}
    for framework_deps in deps.values():
        if not isinstance(framework_deps, dict):
            continue
        for name, info in framework_deps.items():
            if not isinstance(info, dict):
                continue
            version = info.get("resolved") or info.get("version")
            if version:
                seen[name] = version
    return [
        ParsedComponent(ECOSYSTEM_NUGET, name, version, SCOPE_UNKNOWN, RELATION_UNKNOWN, _purl("nuget", name, version))
        for name, version in seen.items()
    ]


# --- gradle.lockfile --------------------------------------------------------

def parse_gradle_lockfile(content: bytes) -> List[ParsedComponent]:
    try:
        text = content.decode("utf-8", errors="ignore")
    except Exception:
        return []
    components: List[ParsedComponent] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("empty="):
            continue
        if ":" not in line or "=" not in line:
            continue
        coordinate = line.split("=", 1)[0]
        parts = coordinate.split(":")
        if len(parts) != 3:
            continue
        group, artifact, version = parts
        name = f"{group}:{artifact}"
        components.append(
            ParsedComponent(ECOSYSTEM_MAVEN, name, version, SCOPE_UNKNOWN, RELATION_UNKNOWN, _purl("maven", artifact, version, namespace=group))
        )
    return components


PARSERS: Dict[str, Callable[[bytes], List[ParsedComponent]]] = {
    "npm": parse_npm_lock,
    "yarn": parse_yarn_lock,
    "poetry": parse_poetry_lock,
    "cargo": parse_cargo_lock,
    "pipenv": parse_pipfile_lock,
    "composer": parse_composer_lock,
    "bundler": parse_gemfile_lock,
    "go": parse_go_mod,
    "nuget": parse_packages_lock_json,
    "gradle": parse_gradle_lockfile,
}


# --- Guvenli komut ipucu (master_prompt.md 6 A1, 5 "Uygulama guvenligi") ---
#
# "Komut ipucunde paket adi/surum ekosistem kuralina gore DOGRULANMADAN
# gosterilmez; yalnizca metin olarak gosterilir, otomatik calistirilmaz."
# Scanner ciktisi (paket adi) GUVENILMEYEN girdidir -- `lodash; rm -rf /`
# gibi bir ad, kopyala-yapistir saldirisina donusebilir. HTML escape
# YETERLI DEGIL (saldiri hedefi tarayici degil, kullanicinin terminali);
# ekosistemin GERCEK ad/surum grameri ile eslesmiyorsa ipucu HIC URETILMEZ.
#
# BILEREK burada (adapters/osv_scanner'a bagimli olmayan core/finding_model.py
# DEGIL): app servisi orchestrator/worker modullerini import etmez (bkz.
# deploy/Dockerfile.app), bu modul zaten core/finding_model.py'nin ECOSYSTEM_*
# sabitlerinin kaynagi ve adapters'a hic bagli degil -- A1 aksiyon gruplari
# (app/routes_actions.py) sadece bunu kullanir.

_PACKAGE_NAME_PATTERNS: Dict[str, re.Pattern] = {
    ECOSYSTEM_NPM: re.compile(r"^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$"),
    ECOSYSTEM_PYPI: re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$"),
    ECOSYSTEM_GO: re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._/-]*[A-Za-z0-9])?$"),
    ECOSYSTEM_CARGO: re.compile(r"^[A-Za-z0-9_-]+$"),
    ECOSYSTEM_PACKAGIST: re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*)?/[A-Za-z0-9]([A-Za-z0-9._-]*)?$"),
    ECOSYSTEM_MAVEN: re.compile(r"^[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+$"),
    ECOSYSTEM_NUGET: re.compile(r"^[A-Za-z0-9_.-]+$"),
    ECOSYSTEM_RUBYGEMS: re.compile(r"^[A-Za-z0-9_.-]+$"),
}

# Surum string'i ekosistemden bagimsiz GUVENLI karakter kumesiyle sinirlanir
# (boşluk/`;`/`|`/backtick/`$`/`&` gibi shell meta-karakterleri HICBIR
# ekosistemde gecerli bir surum parcasi degildir).
_SAFE_VERSION_PATTERN = re.compile(r"^[A-Za-z0-9.+_-]+$")

_INSTALL_HINT_TEMPLATES: Dict[str, str] = {
    ECOSYSTEM_NPM: "npm install {name}@{version}",
    ECOSYSTEM_PYPI: "pip install {name}=={version}",
    ECOSYSTEM_GO: "go get {name}@v{version}",
    ECOSYSTEM_CARGO: "cargo update -p {name} --precise {version}",
    ECOSYSTEM_PACKAGIST: "composer require {name}:{version}",
    ECOSYSTEM_MAVEN: "{name} icin pom.xml/build.gradle'da surumu {version} yapin",
    ECOSYSTEM_NUGET: "dotnet add package {name} --version {version}",
    ECOSYSTEM_RUBYGEMS: "gem update {name} --version {version}",
}


def is_safe_package_name(ecosystem: str, name: str) -> bool:
    pattern = _PACKAGE_NAME_PATTERNS.get(ecosystem)
    if pattern is None or not name:
        return False
    return bool(pattern.match(name))


def is_safe_version_string(version: str) -> bool:
    return bool(version) and bool(_SAFE_VERSION_PATTERN.match(version))


def build_install_hint(ecosystem: str, name: str, version: str) -> Optional[str]:
    """Ad/surum ekosistem grameriyle eslesmiyorsa None doner (ipucu
    gosterilmez) -- cagiran taraf bunu asla otomatik calistirmaz, SADECE
    salt metin olarak gosterir (master_prompt.md 5)."""
    if not is_safe_package_name(ecosystem, name) or not is_safe_version_string(version):
        return None
    template = _INSTALL_HINT_TEMPLATES.get(ecosystem)
    if template is None:
        return None
    return template.format(name=name, version=version)


_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d+$")


def display_vulnerability_id(canonical_id: str, aliases: Optional[List[str]]) -> str:
    """Panelde gosterilecek birincil kimlik: kullanicilar GHSA-xxxx/OSV
    yerine CVE-xxxx'e daha alisik, bu yuzden aliases icinde bir CVE varsa
    ONU gosteririz. Eslestirme/dedup icin HALA canonical_vulnerability_id
    kullanilir (core/finding_model.py) -- bu SADECE goruntuleme katmani,
    depolanan veriyi degistirmez. CVE alias'i yoksa (ör. sadece OSV'de
    bilinen bir GHSA) canonical_id'ye geri doner."""
    if _CVE_PATTERN.match(canonical_id):
        return canonical_id
    for alias in aliases or []:
        if _CVE_PATTERN.match(alias):
            return alias
    return canonical_id

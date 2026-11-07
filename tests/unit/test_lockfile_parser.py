"""core/lockfile_parser.py testleri.

Not: Bu parser'lar SURUM ARALIGI karsilastirmasi YAPMAZ (sadece lockfile'da
yazan ad+surumu okur) -- kural 3 ile celismez, gercek "zafiyetli mi"
sorusunu adapters/osv_scanner.py (Hat B) cevaplar.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.lockfile_parser import (  # noqa: E402
    parse_cargo_lock,
    parse_composer_lock,
    parse_gemfile_lock,
    parse_go_mod,
    parse_gradle_lockfile,
    parse_npm_lock,
    parse_packages_lock_json,
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_yarn_lock,
)


def test_parse_npm_lock_v2_packages_shape_with_dev_flag():
    content = json.dumps(
        {
            "lockfileVersion": 2,
            "packages": {
                "": {"name": "root"},
                "node_modules/lodash": {"version": "4.17.15"},
                "node_modules/jest": {"version": "29.0.0", "dev": True},
                "node_modules/lodash/node_modules/nested-dep": {"version": "1.0.0"},
            },
        }
    ).encode("utf-8")
    components = parse_npm_lock(content)
    by_name = {c.name: c for c in components}
    assert by_name["lodash"].version == "4.17.15"
    assert by_name["lodash"].scope == "prod"
    assert by_name["lodash"].purl == "pkg:npm/lodash@4.17.15"
    assert by_name["jest"].scope == "dev"
    assert by_name["nested-dep"].relation == "transitive"


def test_parse_npm_lock_real_fixture_lodash_4_17_15():
    fixture_path = Path(__file__).resolve().parents[1] / "fixtures" / "osv_scanner" / "npm_lodash_package-lock.json"
    components = parse_npm_lock(fixture_path.read_bytes())
    names_versions = {(c.name, c.version) for c in components}
    assert ("lodash", "4.17.15") in names_versions


def test_parse_yarn_lock_multi_spec_block():
    content = (
        b'"lodash@^4.17.15", "lodash@^4.17.21":\n  version "4.17.21"\n  resolved "x"\n\n'
        b'left-pad@^1.3.0:\n  version "1.3.0"\n'
    )
    components = parse_yarn_lock(content)
    names_versions = {(c.name, c.version) for c in components}
    assert ("lodash", "4.17.21") in names_versions
    assert ("left-pad", "1.3.0") in names_versions


def test_parse_poetry_lock_blocks():
    content = b'[[package]]\nname = "requests"\nversion = "2.31.0"\n\n[[package]]\nname = "urllib3"\nversion = "2.0.7"\n'
    components = parse_poetry_lock(content)
    assert {(c.name, c.version, c.purl) for c in components} == {
        ("requests", "2.31.0", "pkg:pypi/requests@2.31.0"),
        ("urllib3", "2.0.7", "pkg:pypi/urllib3@2.0.7"),
    }


def test_parse_cargo_lock_blocks():
    content = b'[[package]]\nname = "serde"\nversion = "1.0.193"\n'
    components = parse_cargo_lock(content)
    assert components == [
        __import__("core.lockfile_parser", fromlist=["ParsedComponent"]).ParsedComponent(
            "crates.io", "serde", "1.0.193", "unknown", "unknown", "pkg:cargo/serde@1.0.193"
        )
    ]


def test_parse_pipfile_lock_default_and_develop():
    content = json.dumps(
        {"default": {"django": {"version": "==4.2.1"}}, "develop": {"pytest": {"version": "==7.4.0"}}}
    ).encode("utf-8")
    components = parse_pipfile_lock(content)
    by_name = {c.name: c for c in components}
    assert by_name["django"].version == "4.2.1"
    assert by_name["django"].scope == "prod"
    assert by_name["pytest"].scope == "dev"


def test_parse_composer_lock_packages_and_dev():
    content = json.dumps(
        {
            "packages": [{"name": "vendor/pkg", "version": "v1.2.3"}],
            "packages-dev": [{"name": "vendor/devpkg", "version": "2.0.0"}],
        }
    ).encode("utf-8")
    components = parse_composer_lock(content)
    by_name = {c.name: c for c in components}
    assert by_name["vendor/pkg"].version == "1.2.3"
    assert by_name["vendor/pkg"].scope == "prod"
    assert by_name["vendor/devpkg"].scope == "dev"


def test_parse_gemfile_lock_specs_section():
    content = (
        b"GEM\n  remote: https://rubygems.org/\n  specs:\n"
        b"    activesupport (6.1.4)\n      concurrent-ruby (~> 1.0)\n"
        b"    rake (13.0.6)\n\nPLATFORMS\n  ruby\n"
    )
    components = parse_gemfile_lock(content)
    names_versions = {(c.name, c.version) for c in components}
    assert ("activesupport", "6.1.4") in names_versions
    assert ("rake", "13.0.6") in names_versions
    assert ("concurrent-ruby", "~> 1.0") not in names_versions  # nested dep, specs disinda


def test_parse_go_mod_block_and_inline():
    content = (
        b"module example.com/foo\n\ngo 1.21\n\n"
        b"require (\n\texample.com/bar v1.2.3\n\texample.com/baz v0.1.0 // indirect\n)\n\n"
        b"require example.com/qux v2.0.0\n"
    )
    components = parse_go_mod(content)
    names_versions = {(c.name, c.version) for c in components}
    assert names_versions == {
        ("example.com/bar", "v1.2.3"),
        ("example.com/baz", "v0.1.0"),
        ("example.com/qux", "v2.0.0"),
    }


def test_parse_go_mod_real_fixture_gin():
    fixture_path = Path(__file__).resolve().parents[1] / "fixtures" / "osv_scanner" / "go_gin.mod"
    components = parse_go_mod(fixture_path.read_bytes())
    names_versions = {(c.name, c.version) for c in components}
    assert ("github.com/gin-gonic/gin", "v1.6.3") in names_versions


def test_parse_packages_lock_json_unions_frameworks():
    content = json.dumps(
        {
            "dependencies": {
                "net6.0": {"Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.1"}},
                "net8.0": {"Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.1"}},
            }
        }
    ).encode("utf-8")
    components = parse_packages_lock_json(content)
    assert len(components) == 1
    assert components[0].name == "Newtonsoft.Json"
    assert components[0].version == "13.0.1"


def test_parse_gradle_lockfile_group_artifact_version():
    content = b"org.slf4j:slf4j-api:1.7.36=compileClasspath\ncom.google.guava:guava:31.1=compileClasspath\nempty=testCompileClasspath\n"
    components = parse_gradle_lockfile(content)
    names_versions = {(c.name, c.version) for c in components}
    assert ("org.slf4j:slf4j-api", "1.7.36") in names_versions
    assert components[0].purl.startswith("pkg:maven/org.slf4j/slf4j-api@")

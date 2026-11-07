"""tools/inventory.py'deki saf (ag cagrisi yapmayan) fonksiyonlarin testleri.

Stdlib unittest kullanilir: Asama 0'da henuz bagimlilik pinleme/Docker
iskeleti kurulu degil, bu yuzden pytest'e bagimli olmadan calisabilmeli.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tools"))

import inventory  # noqa: E402


class ClassifyPathsTests(unittest.TestCase):
    def test_npm_lockfile_detected(self):
        result = inventory.classify_paths(["package.json", "package-lock.json", "src/index.js"])
        self.assertEqual(result.lockfiles, {"npm": ["package-lock.json"]})
        self.assertEqual(result.manifest_only, {"npm": ["package.json"]})

    def test_go_mod_is_lockfile_not_go_sum(self):
        # VERIFIED_FACTS.md: OSV-Scanner go.mod'u lockfile-esdeger kabul eder,
        # go.sum'u degil (go.mod'daki surumler zaten tam/pinli).
        result = inventory.classify_paths(["go.mod", "go.sum"])
        self.assertEqual(result.lockfiles, {"go": ["go.mod"]})
        self.assertEqual(result.manifest_only, {})

    def test_pom_xml_remains_manifest_only(self):
        result = inventory.classify_paths(["pom.xml"])
        self.assertEqual(result.lockfiles, {})
        self.assertEqual(result.manifest_only, {"maven": ["pom.xml"]})

    def test_requirements_txt_is_manifest_only_not_lockfile(self):
        result = inventory.classify_paths(["requirements.txt", "requirements-dev.txt"])
        self.assertEqual(result.lockfiles, {})
        self.assertEqual(
            sorted(result.manifest_only["pip"]),
            ["requirements-dev.txt", "requirements.txt"],
        )

    def test_monorepo_multiple_lockfiles(self):
        paths = [
            "services/api/package-lock.json",
            "services/worker/poetry.lock",
            "services/worker/pyproject.toml",
        ]
        result = inventory.classify_paths(paths)
        self.assertEqual(result.lockfiles["npm"], ["services/api/package-lock.json"])
        self.assertEqual(result.lockfiles["poetry"], ["services/worker/poetry.lock"])

    def test_dockerfile_and_compose_detection(self):
        result = inventory.classify_paths(["Dockerfile", "docker/Dockerfile.worker", "docker-compose.yml"])
        self.assertTrue(result.has_dockerfile)
        self.assertTrue(result.has_compose)

    def test_codeowners_detection_variants(self):
        self.assertTrue(inventory.classify_paths(["CODEOWNERS"]).has_codeowners)
        self.assertTrue(inventory.classify_paths([".github/CODEOWNERS"]).has_codeowners)
        self.assertFalse(inventory.classify_paths(["docs/readme.md"]).has_codeowners)

    def test_symlink_like_path_is_not_specially_treated_here(self):
        # Asama 1/2'de symlink (mode 120000) tespiti tree API'nin "mode" alanindan
        # yapilir; bu envanter scripti sadece path/basename bakar (kural 9: kucuk
        # test edilebilir parca). Burada sadece normal eslesmeyi dogruluyoruz.
        result = inventory.classify_paths(["vendor/evil-symlink/package-lock.json"])
        self.assertIn("npm", result.lockfiles)

    def test_csproj_is_manifest_only(self):
        result = inventory.classify_paths(["src/App/App.csproj", "src/App/packages.lock.json"])
        self.assertEqual(result.lockfiles, {"nuget": ["src/App/packages.lock.json"]})
        self.assertEqual(result.manifest_only, {"nuget": ["src/App/App.csproj"]})


class ComponentEstimatorTests(unittest.TestCase):
    def test_npm_lockfile_v2_packages_shape(self):
        content = json.dumps(
            {
                "lockfileVersion": 2,
                "packages": {
                    "": {"name": "root"},
                    "node_modules/lodash": {"version": "4.17.21"},
                    "node_modules/left-pad": {"version": "1.3.0"},
                },
            }
        ).encode("utf-8")
        self.assertEqual(inventory.estimate_npm_lock_components(content), 2)

    def test_npm_lockfile_v1_dependencies_shape_counts_nested(self):
        content = json.dumps(
            {
                "dependencies": {
                    "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}},
                    "c": {"version": "3.0.0"},
                }
            }
        ).encode("utf-8")
        self.assertEqual(inventory.estimate_npm_lock_components(content), 3)

    def test_npm_lockfile_invalid_json_returns_none(self):
        self.assertIsNone(inventory.estimate_npm_lock_components(b"{not json"))

    def test_yarn_lock_top_level_blocks(self):
        content = (
            b'"lodash@^4.17.21":\n  version "4.17.21"\n\n'
            b'left-pad@^1.3.0:\n  version "1.3.0"\n'
        )
        self.assertEqual(inventory.estimate_yarn_lock_components(content), 2)

    def test_poetry_lock_double_bracket_sections(self):
        content = b'[[package]]\nname = "a"\n\n[[package]]\nname = "b"\n'
        estimator = inventory.ESTIMATORS["poetry"]
        self.assertEqual(estimator(content), 2)

    def test_cargo_lock_double_bracket_sections(self):
        content = b'[[package]]\nname = "a"\n\n[[package]]\nname = "b"\n[[package]]\nname="c"\n'
        estimator = inventory.ESTIMATORS["cargo"]
        self.assertEqual(estimator(content), 3)

    def test_pipfile_lock_default_and_develop(self):
        content = json.dumps({"default": {"a": {}, "b": {}}, "develop": {"c": {}}}).encode("utf-8")
        self.assertEqual(inventory.estimate_pipfile_lock_components(content), 3)

    def test_composer_lock_packages_and_dev(self):
        content = json.dumps({"packages": [{"name": "a"}], "packages-dev": [{"name": "b"}, {"name": "c"}]}).encode(
            "utf-8"
        )
        self.assertEqual(inventory.estimate_composer_lock_components(content), 3)

    def test_gemfile_lock_specs_section(self):
        content = (
            b"GEM\n  remote: https://rubygems.org/\n  specs:\n"
            b"    activesupport (6.1.4)\n      concurrent-ruby (~> 1.0)\n"
            b"    rake (13.0.6)\n\nPLATFORMS\n  ruby\n"
        )
        self.assertEqual(inventory.estimate_gemfile_lock_components(content), 2)

    def test_go_mod_counts_require_block_and_inline(self):
        content = (
            b"module example.com/foo\n\n"
            b"go 1.21\n\n"
            b"require (\n"
            b"\texample.com/bar v1.2.3\n"
            b"\texample.com/baz v0.1.0 // indirect\n"
            b")\n\n"
            b"require example.com/qux v2.0.0\n"
        )
        self.assertEqual(inventory.estimate_go_mod_components(content), 3)

    def test_packages_lock_json_unions_target_frameworks(self):
        content = json.dumps(
            {
                "dependencies": {
                    "net6.0": {"Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.1"}},
                    "net8.0": {"Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.1"}, "Serilog": {}},
                }
            }
        ).encode("utf-8")
        self.assertEqual(inventory.estimate_packages_lock_json_components(content), 2)

    def test_gradle_lockfile_counts_entries_skips_meta(self):
        content = (
            b"# This is a Gradle generated file for dependency locking.\n"
            b"org.slf4j:slf4j-api:1.7.36=compileClasspath,runtimeClasspath\n"
            b"com.google.guava:guava:31.1=compileClasspath\n"
            b"empty=testCompileClasspath\n"
        )
        self.assertEqual(inventory.estimate_gradle_lockfile_components(content), 2)


class RateLimitHelperTests(unittest.TestCase):
    def test_retry_after_header_wins(self):
        wait = inventory.GitHubClient.rate_limit_wait_seconds({"Retry-After": "5"}, now=1000.0)
        self.assertEqual(wait, 6.0)

    def test_rate_limit_reset_header_used_when_no_retry_after(self):
        wait = inventory.GitHubClient.rate_limit_wait_seconds({"X-RateLimit-Reset": "1065"}, now=1000.0)
        self.assertEqual(wait, 66.0)

    def test_falls_back_to_default_when_no_headers(self):
        wait = inventory.GitHubClient.rate_limit_wait_seconds({}, now=1000.0)
        self.assertEqual(wait, 60.0)

    def test_is_rate_limited_detects_secondary_abuse_limit(self):
        self.assertTrue(inventory.GitHubClient.is_rate_limited(403, {"Retry-After": "30"}))

    def test_is_rate_limited_detects_primary_limit_exhausted(self):
        self.assertTrue(inventory.GitHubClient.is_rate_limited(403, {"X-RateLimit-Remaining": "0"}))

    def test_is_rate_limited_false_on_plain_403(self):
        self.assertFalse(inventory.GitHubClient.is_rate_limited(403, {"X-RateLimit-Remaining": "10"}))


class BuildSummaryTests(unittest.TestCase):
    def test_summary_counts_and_ratio(self):
        records = [
            inventory.RepoRecord(
                name="a", full_name="org/a", visibility="private", archived=False, fork=False,
                default_branch="main", languages={}, lockfiles={"npm": ["package-lock.json"]},
                manifest_only={}, has_dockerfile=False, has_compose=False, has_codeowners=False,
                dependabot_alerts_status=200, had_commits_30d=True, had_commits_90d=True,
                tree_truncated=False, estimated_components=5,
            ),
            inventory.RepoRecord(
                name="b", full_name="org/b", visibility="private", archived=True, fork=False,
                default_branch="main", languages={}, lockfiles={}, manifest_only={"maven": ["pom.xml"]},
                has_dockerfile=False, has_compose=False, has_codeowners=False,
                dependabot_alerts_status=404, had_commits_30d=False, had_commits_90d=False,
                tree_truncated=False, estimated_components=0,
            ),
        ]
        summary = inventory.build_summary(records)
        self.assertEqual(summary["total_repos"], 2)
        self.assertEqual(summary["archived_repos"], 1)
        self.assertEqual(summary["repos_without_any_lockfile"], 1)
        self.assertEqual(summary["repos_without_any_lockfile_ratio"], 0.5)
        self.assertEqual(summary["lockfile_ecosystem_distribution"], {"npm": 1})
        self.assertEqual(summary["manifest_only_ecosystem_distribution"], {"maven": 1})
        self.assertEqual(summary["estimated_component_count_upper_bound_total"], 5)
        self.assertEqual(summary["repos_active_last_30d"], 1)


class RecordToRowTests(unittest.TestCase):
    def test_joins_multi_value_fields_with_semicolon(self):
        record = inventory.RepoRecord(
            name="a", full_name="org/a", visibility="public", archived=False, fork=False,
            default_branch="main", languages={"Python": 100, "Go": 10},
            lockfiles={"npm": ["a/package-lock.json", "b/package-lock.json"]},
            manifest_only={}, has_dockerfile=True, has_compose=False, has_codeowners=True,
            dependabot_alerts_status=200, had_commits_30d=True, had_commits_90d=True,
            tree_truncated=False, estimated_components=3, error=None,
        )
        row = inventory.record_to_row(record)
        self.assertEqual(row["languages"], "Go;Python")
        self.assertEqual(row["lockfile_paths"], "a/package-lock.json;b/package-lock.json")
        self.assertEqual(row["errors"], "")


if __name__ == "__main__":
    unittest.main()

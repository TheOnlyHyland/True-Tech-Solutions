"""Derive and verify the permanent Supervisor App release identity."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import sys


APP_SLUG = "true_family_journal"
IMAGE_NAME = "true-family-journal"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
WORKFLOW_PATH = ".github/workflows/release-app.yaml"
GITHUB_URL = re.compile(
    r"^https://github\.com/"
    r"(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)/"
    r"(?P<repository>[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?)$"
)


class ReleaseIdentityError(ValueError):
    """The release identity is missing, aliased, or inconsistent."""


def derive_identity(repository_url: str) -> dict[str, object]:
    """Derive the exact Supervisor and signing identities from one canonical URL."""

    if type(repository_url) is not str or repository_url != repository_url.strip():
        raise ReleaseIdentityError("The repository URL must be trimmed text.")
    match = GITHUB_URL.fullmatch(repository_url)
    if match is None or repository_url.lower().endswith(".git"):
        raise ReleaseIdentityError(
            "Use the canonical public GitHub page URL without aliases or .git."
        )
    owner = match.group("owner")
    repository = match.group("repository")
    repository_slug = hashlib.sha1(repository_url.lower().encode("utf-8")).hexdigest()[:8]
    full_app_slug = f"{repository_slug}_{APP_SLUG}"
    return {
        "schema_version": 1,
        "state": "bound",
        "canonical_repository_url": repository_url,
        "repository_slug": repository_slug,
        "app_slug": APP_SLUG,
        "full_app_slug": full_app_slug,
        "hostname": full_app_slug.replace("_", "-"),
        "image": f"ghcr.io/{owner.lower()}/{IMAGE_NAME}",
        "cosign_oidc_issuer": OIDC_ISSUER,
        "cosign_certificate_identity": (
            f"https://github.com/{owner}/{repository}/{WORKFLOW_PATH}"
            "@refs/heads/main"
        ),
    }


def _top_level_scalars(path: Path) -> dict[str, str]:
    scalars: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        if not raw_line or raw_line[0].isspace() or raw_line.startswith("#"):
            continue
        key, separator, raw_value = raw_line.partition(":")
        if not separator or not raw_value.strip():
            continue
        value = raw_value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        scalars[key] = value
    return scalars


def _string_assignments(path: Path) -> dict[str, str]:
    assignments: dict[str, str] = {}
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        target: ast.expr | None = None
        value: ast.expr | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            target = node.target
            value = node.value
        if (
            isinstance(target, ast.Name)
            and isinstance(value, ast.Constant)
            and type(value.value) is str
        ):
            assignments[target.id] = value.value
    return assignments


def _trusted_app_slugs(path: Path) -> frozenset[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if not isinstance(node, ast.AnnAssign):
            continue
        if not isinstance(node.target, ast.Name):
            continue
        if node.target.id != "TRUSTED_REMOTE_JOURNAL_APP_SLUGS":
            continue
        value = node.value
        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "frozenset"
            and len(value.args) == 1
            and not value.keywords
        ):
            literal = ast.literal_eval(value.args[0])
            if type(literal) is set and all(type(item) is str for item in literal):
                return frozenset(literal)
    raise ReleaseIdentityError("The integration trust set is not a literal frozenset.")


def validate_project(
    project: Path,
    *,
    require_bound: bool = False,
    github_repository: str | None = None,
) -> dict[str, object]:
    """Verify that every release surface agrees with the frozen identity."""

    identity_path = project / "release" / "identity.json"
    try:
        identity = json.loads(identity_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as err:
        raise ReleaseIdentityError("The release identity file is unreadable.") from err
    if type(identity) is not dict or identity.get("state") != "bound":
        if require_bound:
            raise ReleaseIdentityError("A bound release identity is required.")
        raise ReleaseIdentityError("The project release identity is not bound.")
    repository_value = identity.get("canonical_repository_url")
    if type(repository_value) is not str:
        raise ReleaseIdentityError("The canonical repository URL is missing.")
    expected = derive_identity(repository_value)
    if identity != expected:
        raise ReleaseIdentityError("The persisted release identity is not canonical.")

    repository_url = repository_value
    owner_and_repository = repository_url.removeprefix("https://github.com/")
    if github_repository is not None and github_repository.lower() != owner_and_repository.lower():
        raise ReleaseIdentityError("The GitHub workflow repository is not the trusted repository.")

    app = _top_level_scalars(project / APP_SLUG / "config.yaml")
    repository = _top_level_scalars(project / "repository.yaml")
    app_url = f"{repository_url}/tree/main/{APP_SLUG}"
    if app.get("slug") != APP_SLUG:
        raise ReleaseIdentityError("The App base slug does not match the release identity.")
    if app.get("url") != app_url or app.get("image") != identity["image"]:
        raise ReleaseIdentityError("The App URL or image does not match the release identity.")
    if repository.get("url") != repository_url:
        raise ReleaseIdentityError("repository.yaml does not use the canonical URL.")

    app_version = app.get("version")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", app_version or ""):
        raise ReleaseIdentityError("The App version is not strict semantic version text.")
    server_path = project / APP_SLUG / "server.py"
    server_constants = _string_assignments(server_path)
    dockerfile = (project / APP_SLUG / "Dockerfile").read_text(encoding="utf-8")
    remote_path = (
        project / "custom_components" / "true_family" / "reference_journal_remote.py"
    )
    integration_manifest = json.loads(
        (project / "custom_components" / "true_family" / "manifest.json").read_text(
            encoding="utf-8"
        )
    )
    integration_constants = _string_assignments(
        project / "custom_components" / "true_family" / "const.py"
    )
    expected_server_constants = {
        "APP_BASE_SLUG": identity["app_slug"],
        "APP_FULL_SLUG": identity["full_app_slug"],
        "APP_HOSTNAME": identity["hostname"],
        "APP_VERSION": app_version,
    }
    if any(
        server_constants.get(name) != value
        for name, value in expected_server_constants.items()
    ):
        raise ReleaseIdentityError("The App server identity constants are inconsistent.")
    if f"ARG BUILD_VERSION={app_version}" not in dockerfile:
        raise ReleaseIdentityError("The Docker build version is inconsistent.")
    if integration_manifest.get("version") != app_version:
        raise ReleaseIdentityError("The integration and App versions are inconsistent.")
    if integration_constants.get("VERSION") != app_version:
        raise ReleaseIdentityError("The integration version constant is inconsistent.")
    if _trusted_app_slugs(remote_path) != frozenset({identity["full_app_slug"]}):
        raise ReleaseIdentityError("The integration trust set is not the exact release App slug.")
    if (project / "companion_app").exists():
        raise ReleaseIdentityError("The legacy companion_app directory still exists.")
    license_text = (project / "LICENSE").read_text(encoding="utf-8")
    if not license_text.startswith(
        "Copyright (c) 2026 True Tech Solutions. All rights reserved."
    ):
        raise ReleaseIdentityError("The approved proprietary licence is missing.")

    workflow = (project / WORKFLOW_PATH).read_text(encoding="utf-8")
    for required in (
        "check --require-bound",
        "home-assistant/builder/actions/build-image@4de35182ce1e329181bffcbcc84d33db5e2c7e10",
        "home-assistant/builder/actions/publish-multi-arch-manifest@4de35182ce1e329181bffcbcc84d33db5e2c7e10",
        'cosign: "true"',
        'path: "./true_family_journal"',
        'context: "./true_family_journal"',
        'version: "${{ steps.normalize.outputs.version }}"',
        "id-token: write",
        "astral-sh/setup-uv@c771a70e6277c0a99b617c7a806ffedaca235ff9",
        'version: "0.11.33"',
        "uv sync --locked",
        "git ls-remote --exit-code --tags",
        '"refs/tags/${VERSION}"',
        'case "${inspection,,}" in',
        "python -m unittest discover -s tests -p \"test_*.py\"",
    ):
        if required not in workflow:
            raise ReleaseIdentityError("The guarded signed release workflow is incomplete.")
    if re.search(r"(?m)^\s+latest\s*$", workflow) or 'image-tags: "latest"' in workflow:
        raise ReleaseIdentityError("The release workflow must not publish a mutable latest tag.")
    return identity


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    derive = subparsers.add_parser("derive", help="derive one canonical identity")
    derive.add_argument("repository_url")
    check = subparsers.add_parser("check", help="validate the current project")
    check.add_argument("--require-bound", action="store_true")
    check.add_argument("--github-repository")
    arguments = parser.parse_args()
    try:
        if arguments.command == "derive":
            print(json.dumps(derive_identity(arguments.repository_url), indent=2))
        else:
            project = Path(__file__).resolve().parents[1]
            identity = validate_project(
                project,
                require_bound=arguments.require_bound,
                github_repository=arguments.github_repository,
            )
            print(f"release identity {identity['full_app_slug']} verified")
    except ReleaseIdentityError as err:
        print(str(err), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

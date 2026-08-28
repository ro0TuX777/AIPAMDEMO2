"""Git history metadata — the attribution surface a file scanner cannot reach.

Every other Attribution detector reads the files that are *in* the artifact.
This one reads the repository that ships alongside them, and the two see
different things. A `.git` directory carries the author and committer of every
commit, the remote it was pushed to, the paths of files that were deleted years
ago, and a timestamp per commit whose UTC offset is a standing declaration of
where the work was done. None of that is in any file the other scanners open —
and `fpfilter` deliberately suppresses anything found *under* `.git`, on the
grounds that it is tool-owned output rather than the artifact. That rule is
correct for a secret scanner walking blobs and wrong for this question, which
is why gitmeta reports project-scoped findings and never a path inside `.git`.

**Absence of a repository is a measured result, not a coverage hole.** This is
the opposite of the dirty-word scanner, where a missing wordlist means the
operator never told us what to look for. Here, "no `.git` in the artifact" is
a fact about the artifact: there is no history to leak. Only a missing `git`
binary is real coverage loss, because then we could not look.

**Severity is deliberately not disqualifying by default.** A repository has
authors by definition, so treating every author identity as critical would
disqualify any artifact that shipped its history — including a vendored
open-source tree, whose contributors are not the operator. The one case that
*is* decisive is an identity matching a term the operator declared sensitive,
and that gets its own rule id and its own critical severity, on exactly the
argument the dirty-word scanner makes: nothing in this pipeline is more precise
than being told.

**Git treats the repository's own config as configuration, and we do not.**
`.git/config` is attacker-authored, and several of its keys name programs git
will execute (`core.pager`, `core.fsmonitor`, `core.sshCommand`,
`core.alternateRefsCommand`, `log.showSignature` reaching for gpg). Repo-local
config cannot be switched off, so every invocation overrides those keys on the
command line, where `-c` outranks the repository. Remotes are read by parsing
the file as text rather than by asking git for them, for the same reason: it is
evidence, not settings.

Reference: docs/BLUESCRUB_DACV_IMPLEMENTATION_PLAN.md §14 Sprint 5 ·
docs/BLUESCRUB_ISOLATION_CONTRACT.md §3.1 (`repo_history`)
"""

from __future__ import annotations

import json
import logging
import os
import shutil
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from backend.app.bluescrub.isolation import (
    AnalyzerStatus,
    ResourceLimits,
    require_privilege_drop,
    run_analyzer,
)
from backend.app.bluescrub.models import Location, Observable, RawFinding
from backend.app.bluescrub.pillars import FAMILY_PILLAR, DetectorClass, IssueFamily
from backend.app.bluescrub.scanners.base import ScannerOutcome
from backend.app.bluescrub.scanners.dirty_word import WORDLIST_ENV

logger = logging.getLogger(__name__)

SENSOR = "gitmeta"
RULE_NAMESPACE = "GitMeta"

#: Ceilings. History is unbounded in principle and the rlimits would kill a
#: runaway walk anyway, but a bounded walk that reports its bound is more
#: useful than a timeout that reports nothing.
MAX_REPOS = 8
MAX_COMMITS = 20_000
MAX_DIFF_COMMITS = 5_000
MAX_CONFIG_BYTES = 1024 * 1024

#: History walks are I/O bound over a whole object store, so the parse-only
#: default's two minutes is too tight for a large repository. Declared here
#: rather than in the registry so the two cannot drift apart.
DEFAULT_LIMITS = ResourceLimits(wall_clock_seconds=300, cpu_seconds=300)

#: Below this, a consistent timezone is coincidence rather than a pattern.
MIN_COMMITS_FOR_TIMEZONE = 10
#: Share of commits one offset must hold before it is worth reporting.
TIMEZONE_DOMINANCE = 0.8

#: ASCII unit separator. Git idents cannot contain it, or a newline.
FIELD_SEP = "\x1f"
LOG_FORMAT = FIELD_SEP.join(("%an", "%ae", "%cn", "%ce", "%aI", "%cI"))

#: Subcommands that can open a network connection. gitmeta issues none of them,
#: and a test asserts it — the isolation contract requires that verification be
#: hard-disabled for the `repo_history` class rather than merely unconfigured.
NETWORK_SUBCOMMANDS: frozenset[str] = frozenset({
    "clone", "fetch", "pull", "push", "ls-remote", "remote", "submodule",
    "archive", "send-pack", "request-pull", "svn", "p4",
})

#: Config keys whose values name a program git will run. Overridden on the
#: command line, where `-c` outranks the repository's own config.
_NEUTRALISED_CONFIG: tuple[str, ...] = (
    "core.pager=cat",
    "core.fsmonitor=",
    "core.hooksPath=/dev/null",
    "core.sshCommand=",
    "core.alternateRefsCommand=",
    "core.askPass=",
    "uploadpack.packObjectsHook=",
    "diff.external=",
    "log.showSignature=false",
    "gpg.program=/bin/false",
    # Blocks every transport, so a misread of this module can still not reach
    # the network.
    "protocol.allow=never",
)

_GIT_ENV: dict[str, str] = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_ATTR_NOSYSTEM": "1",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_ASKPASS": "",
    "GIT_ALLOW_PROTOCOL": "",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_PAGER": "cat",
}

#: Forges anyone can sign up to. A remote pointing at one still names the
#: account or organisation that owns the repository; a remote pointing anywhere
#: else additionally discloses infrastructure.
PUBLIC_FORGES: frozenset[str] = frozenset({
    "github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "gitee.com",
    "git.sr.ht", "sourceforge.net", "salsa.debian.org", "hf.co",
    "huggingface.co", "gitea.com",
})

#: Userinfo that is a protocol convention rather than a person.
_GENERIC_REMOTE_USERS: frozenset[str] = frozenset({
    "git", "gitlab-ci-token", "oauth2", "x-access-token", "x-oauth-basic",
})

#: Filenames whose deletion from history is worth surfacing. Exact names and
#: suffixes are near-certain; the stem list is a guess, so it is applied only
#: to files that are not obviously source.
_SENSITIVE_NAMES: frozenset[str] = frozenset({
    ".env", ".envrc", ".netrc", "_netrc", ".npmrc", ".pypirc", ".dockercfg",
    ".htpasswd", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "shadow",
    "credentials", "secrets.yml", "secrets.yaml", "secrets.json",
    "service-account.json", "known_hosts", "terraform.tfvars",
})
_SENSITIVE_SUFFIXES: tuple[str, ...] = (
    ".pem", ".key", ".pfx", ".p12", ".jks", ".keystore", ".kdbx", ".ovpn",
    ".ppk", ".asc", ".gpg", ".kubeconfig",
)
_SENSITIVE_STEMS: tuple[str, ...] = (
    "secret", "credential", "password", "passwd", "apikey", "api_key",
    "token", "private_key", "privatekey",
)
#: Extensions that make a "secret"-ish name a source file about secrets rather
#: than a secret. ``secrets.py`` is code; ``secrets.txt`` is not obviously.
_CODE_SUFFIXES: frozenset[str] = frozenset({
    ".c", ".h", ".cc", ".cpp", ".hpp", ".py", ".go", ".rs", ".java", ".js",
    ".ts", ".tsx", ".jsx", ".cs", ".rb", ".php", ".swift", ".kt", ".m", ".mm",
    ".md", ".rst", ".html", ".css", ".scss", ".sql", ".proto",
})

#: Forge-issued addresses that are a handle rather than a mailbox. Kept, not
#: suppressed: the local part still names the account.
_FORGE_NOREPLY_DOMAINS: tuple[str, ...] = (
    "users.noreply.github.com", "noreply.github.com",
    "users.noreply.gitlab.com", "noreply.gitlab.com",
    "noreply.codeberg.org",
)


# ── repository discovery ──────────────────────────────────────────────────

@dataclass(frozen=True)
class GitRepo:
    """One repository found inside the staged artifact."""

    work_dir: Path
    git_dir: Path
    #: Path of the working tree relative to the source root; "." at the top.
    rel: str


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root)) or "."
    except ValueError:  # pragma: no cover - callers only pass descendants
        return str(path)


def _is_bare(path: Path) -> bool:
    return (
        (path / "HEAD").is_file()
        and (path / "objects").is_dir()
        and (path / "refs").is_dir()
    )


def resolve_gitdir_file(dot_git: Path, source_root: Path) -> Path | None:
    """Resolve a ``.git`` *file* pointer, refusing one that escapes the tree.

    Submodules and linked worktrees replace the directory with a file holding
    ``gitdir: <path>``. That path is attacker-controlled and may be absolute,
    so a repository claiming its object store lives in ``/etc`` is refused
    rather than followed.
    """
    try:
        text = dot_git.read_text(errors="replace")[:4096]
    except OSError:
        return None
    for line in text.splitlines():
        if not line.lower().startswith("gitdir:"):
            continue
        target = line.split(":", 1)[1].strip()
        if not target:
            return None
        candidate = Path(target)
        if not candidate.is_absolute():
            candidate = dot_git.parent / candidate
        try:
            resolved = candidate.resolve()
            root = source_root.resolve()
        except OSError:
            return None
        if root != resolved and root not in resolved.parents:
            logger.warning("gitmeta: refusing gitdir pointer escaping the artifact")
            return None
        return resolved if resolved.is_dir() else None
    return None


def find_repositories(source_root: Path, limit: int = MAX_REPOS) -> tuple[list[GitRepo], bool]:
    """Locate repositories in the staged tree. Returns (repos, truncated)."""
    if not source_root.is_dir():
        return [], False

    repos: list[GitRepo] = []
    truncated = False

    if _is_bare(source_root):
        repos.append(GitRepo(work_dir=source_root, git_dir=source_root, rel="."))

    for dot_git in sorted(source_root.rglob(".git")):
        if len(repos) >= limit:
            truncated = True
            break
        if dot_git.is_symlink():
            # A symlinked .git points outside the staged tree by construction.
            continue
        if dot_git.is_dir():
            git_dir: Path | None = dot_git
        elif dot_git.is_file():
            git_dir = resolve_gitdir_file(dot_git, source_root)
        else:  # pragma: no cover - rglob only yields existing entries
            git_dir = None
        if git_dir is None:
            continue
        work = dot_git.parent
        repos.append(GitRepo(work_dir=work, git_dir=git_dir, rel=_rel(work, source_root)))

    return repos, truncated


# ── git invocation ────────────────────────────────────────────────────────

def git_argv(binary: str, repo: GitRepo, *args: str) -> list[str]:
    """Build a read-only git command line that ignores the repo's own config.

    ``safe.directory`` is not optional here: the analyzer drops to a dedicated
    account, so the staged tree is owned by somebody else and git refuses a
    repository with "dubious ownership" before running anything.
    """
    argv = [binary, "--no-pager"]
    for setting in _NEUTRALISED_CONFIG:
        argv += ["-c", setting]
    argv += ["-c", f"safe.directory={repo.git_dir}"]
    argv += ["-c", f"safe.directory={repo.work_dir}"]
    argv += ["--git-dir", str(repo.git_dir), *args]
    return argv


def _run_git(binary: str, repo: GitRepo, args: list[str], limits: ResourceLimits):
    return run_analyzer(
        git_argv(binary, repo, *args),
        cwd=repo.work_dir,
        limits=limits,
        require_privilege_drop=require_privilege_drop(),
        env_extra=dict(_GIT_ENV),
    )


def git_version(binary: str) -> str | None:
    result = run_analyzer(
        [binary, "--version"],
        limits=ResourceLimits(wall_clock_seconds=30, cpu_seconds=30),
        require_privilege_drop=require_privilege_drop(),
        env_extra=dict(_GIT_ENV),
    )
    if not result.ok:
        return None
    return (result.stdout or b"").decode("utf-8", "replace").strip()[:64] or None


# ── pure parsers ──────────────────────────────────────────────────────────

@dataclass
class Identity:
    name: str
    email: str
    commits: int = 0
    roles: set[str] = field(default_factory=set)

    @property
    def display(self) -> str:
        return f"{self.name} <{self.email}>".strip()


@dataclass
class HistoryProfile:
    identities: list[Identity] = field(default_factory=list)
    commits: int = 0
    offsets: Counter = field(default_factory=Counter)
    hours: Counter = field(default_factory=Counter)
    malformed: int = 0


def parse_log(text: str) -> HistoryProfile:
    """Parse ``git log --format=<LOG_FORMAT>`` output.

    One record per line, six unit-separated fields. Anything else is counted
    rather than raised: a single malformed record must not cost us the rest of
    the history.
    """
    profile = HistoryProfile()
    seen: dict[tuple[str, str], Identity] = {}

    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split(FIELD_SEP)
        if len(parts) != 6:
            profile.malformed += 1
            continue
        an, ae, cn, ce, author_date, _committer_date = (p.strip() for p in parts)
        profile.commits += 1

        for name, email, role in ((an, ae, "author"), (cn, ce, "committer")):
            if not name and not email:
                continue
            key = (name, email.lower())
            identity = seen.get(key)
            if identity is None:
                identity = seen[key] = Identity(name=name, email=email)
            identity.commits += 1
            identity.roles.add(role)

        offset = _offset_of(author_date)
        if offset:
            profile.offsets[offset] += 1
        hour = _hour_of(author_date)
        if hour is not None:
            profile.hours[hour] += 1

    # Deterministic order: most prolific first, then by identity, so two runs
    # over the same history emit findings in the same sequence.
    profile.identities = sorted(
        seen.values(), key=lambda i: (-i.commits, i.name.lower(), i.email.lower())
    )
    return profile


def _offset_of(iso: str) -> str | None:
    """Return the ``+HH:MM`` suffix of a strict-ISO date, if present."""
    if len(iso) < 6:
        return None
    tail = iso[-6:]
    if tail[0] in "+-" and tail[3] == ":" and tail[1:3].isdigit() and tail[4:].isdigit():
        return tail
    return None


def _hour_of(iso: str) -> int | None:
    """Local hour of a strict-ISO date — local, because that is the leak."""
    if len(iso) < 13 or iso[10] != "T":
        return None
    try:
        return int(iso[11:13])
    except ValueError:  # pragma: no cover - guarded by the slice check
        return None


def is_forge_handle(email: str) -> bool:
    """True for a forge no-reply address.

    Not a suppression: ``12345+alice@users.noreply.github.com`` hides the
    mailbox and publishes the account name, which is the identity either way.
    """
    lowered = email.lower()
    return any(lowered.endswith(domain) for domain in _FORGE_NOREPLY_DOMAINS)


def is_synthesised_ident(email: str) -> bool:
    """True for git's fallback ident, ``user@hostname.(none)``.

    Git synthesises this when ``user.email`` is unset, so it discloses the
    account name and the machine hostname of the box the commit was made on.
    It looks like a placeholder and is the opposite of one.
    """
    return email.lower().endswith(".(none)") or email.lower().endswith("@(none)")


def parse_git_config(text: str) -> dict[str, list[str]]:
    """Parse ``.git/config`` into ``section.subsection.key -> [values]``.

    Hand-written rather than delegated to ``configparser``, which treats git's
    tab-indented entries as continuations of the previous value and silently
    returns nonsense, and rather than to ``git config``, which would mean
    handing an attacker-authored file back to the program we are keeping it
    away from.
    """
    values: dict[str, list[str]] = {}
    section = ""

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line[0] in "#;":
            continue

        if line.startswith("["):
            end = line.find("]")
            if end == -1:
                continue
            header = line[1:end].strip()
            if '"' in header:
                name, _, sub = header.partition('"')
                sub = sub.rsplit('"', 1)[0]
                section = f"{name.strip().lower()}.{sub}"
            else:
                section = header.lower().replace(" ", ".")
            continue

        if "=" not in line:
            # A bare key is boolean true in git's grammar.
            values.setdefault(f"{section}.{line.lower()}", []).append("true")
            continue

        key, _, value = line.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if not key or not section:
            continue
        values.setdefault(f"{section}.{key}", []).append(value)

    return values


def split_remote_credentials(url: str) -> tuple[str, str | None]:
    """Strip userinfo from a remote URL.

    Returns the sanitised URL and whatever was removed. The userinfo is
    stripped whole rather than parsed into user and password: a GitHub token
    is a bare userinfo with no colon, so a rule that only took the part after
    a colon would write the token into the URL finding as a username.
    """
    scheme, sep, rest = url.partition("://")
    if not sep:
        # scp-like syntax: [user@]host:path. A bare ssh username there is a
        # login name, not a secret, so it stays in the URL as evidence.
        user, at, remainder = url.partition("@")
        if not at or "/" in user or ":" not in user:
            return url, None
        return remainder, user

    authority, slash, path = rest.partition("/")
    if "@" not in authority:
        return url, None
    userinfo, _, host = authority.rpartition("@")
    credential = None if userinfo in _GENERIC_REMOTE_USERS else userinfo
    return f"{scheme}://{host}{slash}{path}", credential


def host_of(url: str) -> str | None:
    """Host of a remote URL, for both URL and scp-like forms."""
    sanitised, _ = split_remote_credentials(url)
    scheme, sep, rest = sanitised.partition("://")
    if sep:
        if scheme.lower() == "file":
            return None
        authority = rest.split("/", 1)[0]
    else:
        if sanitised.startswith("/") or sanitised.startswith("."):
            return None
        authority, _, remainder = sanitised.partition(":")
        if not remainder:
            return None
    host = authority.rpartition("@")[2].split(":", 1)[0].strip().lower()
    return host or None


def is_public_forge(host: str | None) -> bool:
    if not host:
        return False
    host = host.lower()
    return any(host == forge or host.endswith(f".{forge}") for forge in PUBLIC_FORGES)


def is_sensitive_path(path: str) -> bool:
    """Whether a deleted path is worth surfacing as recoverable from history."""
    name = path.rsplit("/", 1)[-1].lower()
    if not name:
        return False
    if name in _SENSITIVE_NAMES:
        return True
    if name.endswith(_SENSITIVE_SUFFIXES):
        return True
    suffix = f".{name.rsplit('.', 1)[1]}" if "." in name[1:] else ""
    if suffix in _CODE_SUFFIXES:
        return False
    return any(stem in name for stem in _SENSITIVE_STEMS)


def parse_deleted_paths(text: str, limit: int = 500) -> list[str]:
    """Deleted paths from ``--diff-filter=D --name-only``, deduplicated."""
    seen: list[str] = []
    known: set[str] = set()
    for line in text.splitlines():
        path = line.strip()
        if not path or path in known:
            continue
        # git quotes paths containing control characters or non-ASCII bytes.
        if path.startswith('"') and path.endswith('"') and len(path) > 1:
            path = path[1:-1]
        known.add(path)
        if is_sensitive_path(path):
            seen.append(path)
            if len(seen) >= limit:
                logger.warning(
                    "gitmeta: stopping at %d deleted paths; more were not reported", limit
                )
                break
    return seen


def timezone_profile(profile: HistoryProfile) -> tuple[str, float, str] | None:
    """Dominant non-UTC offset, its share, and a working-hours summary.

    UTC is excluded: it is both the correct normalisation and a real region,
    so it carries no information either way.
    """
    if profile.commits < MIN_COMMITS_FOR_TIMEZONE or not profile.offsets:
        return None
    offset, count = profile.offsets.most_common(1)[0]
    if offset in ("+00:00", "-00:00"):
        return None
    share = count / profile.commits
    if share < TIMEZONE_DOMINANCE:
        return None
    peak = profile.hours.most_common(1)[0][0] if profile.hours else None
    window = f"{peak:02d}:00 local" if peak is not None else "no clear hour"
    return offset, share, window


# ── finding construction ──────────────────────────────────────────────────

def _finding(
    *,
    rule: str,
    family: IssueFamily,
    subject: str,
    title: str,
    description: str,
    matched: str,
    detector: DetectorClass,
    confidence: float,
    severity: str,
    observables: list[Observable] | None = None,
    recommendation: str | None = None,
) -> RawFinding:
    return RawFinding(
        sensor=SENSOR,
        sensor_version="builtin",
        rule_namespace=RULE_NAMESPACE,
        rule_id=rule,
        issue_family=family,
        pillar_hint=FAMILY_PILLAR.get(family),
        detector_class=detector,
        raw_severity=severity,
        confidence=confidence,
        title=title[:512],
        description=description[:4096],
        recommendation=recommendation,
        matched_tokens=matched[:4096],
        observables=observables or [],
        # Project-scoped, never a path: a location under `.git` would be
        # suppressed by the non-artifact filter, which is right for a scanner
        # walking blobs and wrong for the question this module asks.
        location=Location(kind="project", subject=subject[:512]),
    )


def history_present_finding(repo: GitRepo, commits: int) -> RawFinding:
    where = "the artifact root" if repo.rel == "." else repo.rel
    return _finding(
        rule="gitmeta.history_present",
        family=IssueFamily.metadata_leak,
        subject=f"repository:{repo.rel}",
        title="Git repository shipped with the artifact",
        description=(
            f"A git repository is present at {where}. Everything the history "
            "holds ships with it: every commit author and message, every "
            "branch name, and the content of files that were deleted from the "
            "working tree but not from the object store."
            + (f" {commits} commits were read." if commits else "")
        ),
        # Deliberately excludes the commit count: the fingerprint must not
        # change every time somebody commits, or triage resets on each scan.
        matched=f"repository:{repo.rel}",
        detector=DetectorClass.ast_pattern,
        confidence=1.0,
        severity="HIGH",
        recommendation=(
            "Export the tree without its history — `git archive`, or a copy "
            "with `.git` removed — before packaging."
        ),
    )


def identity_findings(
    repo: GitRepo, identities: list[Identity], declared: list[str]
) -> list[RawFinding]:
    findings: list[RawFinding] = []
    for identity in identities:
        if not identity.email and not identity.name:
            continue

        hit = _declared_hit(identity, declared)
        note = ""
        if hit:
            note = (
                " The identity contains a term from the operator's declared "
                "sensitive list, so it is treated as an operator identity "
                "rather than an unknown contributor's."
            )
        elif is_forge_handle(identity.email):
            note = (
                " The address is a forge no-reply, which hides the mailbox "
                "and publishes the account name."
            )
        elif is_synthesised_ident(identity.email):
            note = (
                " Git synthesised this address because `user.email` was "
                "unset, so it carries the account name and the hostname of "
                "the machine the commit was made on."
            )

        roles = " and ".join(sorted(identity.roles)) or "contributor"
        findings.append(_finding(
            rule="gitmeta.declared_identity" if hit else "gitmeta.author_identity",
            family=IssueFamily.attribution_identity,
            subject=f"author:{identity.email.lower() or identity.name.lower()}",
            title=(
                "Declared operator identity in git history" if hit
                else "Identity in git history"
            ),
            description=(
                f"{identity.display} appears as {roles} on {identity.commits} "
                f"commit record(s) in the repository at {repo.rel}.{note}"
            ),
            matched=identity.display,
            # Read out of a parsed commit object, not guessed from a pattern:
            # git labels the field, so the evidence is structural rather than
            # a regex asserting that something looks like an address.
            detector=DetectorClass.ast_pattern,
            confidence=0.99,
            severity="CRITICAL" if hit else "HIGH",
            observables=(
                [Observable(
                    type="email", value=identity.email,
                    normalized=identity.email.lower(),
                    origin="git_metadata", confidence=0.99,
                )] if "@" in identity.email else []
            ),
            recommendation=(
                "Rewrite the history with a neutral ident, or ship an export "
                "that carries no history at all."
            ),
        ))
    return findings


def _declared_hit(identity: Identity, declared: list[str]) -> bool:
    """Whether a declared sensitive term appears in the identity.

    Case-insensitive on purpose: an operator handle is the same leak in any
    casing, and the wordlist's own case-sensitivity setting exists for
    classification markings inside file content, not for idents.
    """
    haystack = identity.display.casefold()
    return any(term and term.casefold() in haystack for term in declared)


def remote_findings(repo: GitRepo, config: dict[str, list[str]]) -> list[RawFinding]:
    findings: list[RawFinding] = []
    seen: set[str] = set()

    for key, urls in sorted(config.items()):
        parts = key.split(".")
        if parts[0] != "remote" or parts[-1] not in ("url", "pushurl"):
            continue
        remote_name = ".".join(parts[1:-1]) or "origin"

        for url in urls:
            sanitised, credential = split_remote_credentials(url)
            host = host_of(url)
            if not host or sanitised in seen:
                continue
            seen.add(sanitised)

            public = is_public_forge(host)
            findings.append(_finding(
                rule="gitmeta.remote_url",
                family=IssueFamily.attribution_infrastructure,
                subject=f"remote:{remote_name}:{sanitised}",
                title="Git remote recorded in the shipped repository",
                description=(
                    f"Remote {remote_name!r} points at {sanitised}. "
                    + (
                        "The host is a public forge, so the account or "
                        "organisation owning the repository is named."
                        if public else
                        f"The host {host} is not a public forge, so it names "
                        "internal infrastructure as well as the owner."
                    )
                ),
                matched=sanitised,
                detector=DetectorClass.ast_pattern,
                confidence=0.95,
                severity="HIGH",
                observables=[Observable(
                    type="domain", value=host, normalized=host,
                    origin="git_metadata", confidence=0.95,
                )],
                recommendation="Remove the remote, or ship without `.git`.",
            ))

            if credential:
                findings.append(_finding(
                    rule="gitmeta.remote_credentials",
                    family=IssueFamily.credential_exposure,
                    subject=f"remote-credential:{remote_name}:{host}",
                    title="Credential embedded in a git remote URL",
                    description=(
                        f"The URL for remote {remote_name!r} carries userinfo "
                        f"for {host}. Anyone holding the artifact holds it."
                    ),
                    # The only place the plaintext appears. Central redaction
                    # masks it and replaces it with a keyed fingerprint before
                    # anything is persisted; the URL finding above never had it.
                    matched=credential,
                    detector=DetectorClass.ast_pattern,
                    confidence=0.95,
                    severity="HIGH",
                    recommendation="Revoke it, then rewrite the config.",
                ))

    return findings


def configured_identities(config: dict[str, list[str]]) -> list[Identity]:
    """Identity set in ``.git/config``, which a log walk cannot see.

    A repository with no commits still names whoever set it up.
    """
    name = (config.get("user.name") or [""])[0]
    email = (config.get("user.email") or [""])[0]
    if not name and not email:
        return []
    identity = Identity(name=name, email=email, commits=0)
    identity.roles.add("configured")
    return [identity]


def deleted_file_findings(repo: GitRepo, paths: list[str]) -> list[RawFinding]:
    return [
        _finding(
            rule="gitmeta.deleted_sensitive_file",
            family=IssueFamily.metadata_leak,
            subject=f"deleted:{repo.rel}:{path}",
            title="Sensitive file deleted from the tree but present in history",
            description=(
                f"{path} was deleted in the repository at {repo.rel}. Deleting "
                "a file removes it from the working tree and not from the "
                "object store, so any commit that contained it still serves "
                "it. The name is a heuristic — the content was not read."
            ),
            matched=path,
            # The name is the whole of the evidence, which is a guess about
            # what the file held.
            detector=DetectorClass.heuristic,
            confidence=0.6,
            severity="HIGH",
            recommendation=(
                "Treat the contents as disclosed and rotate them, then purge "
                "the blob from history if the repository must ship."
            ),
        )
        for path in paths
    ]


def timezone_finding(repo: GitRepo, tz: tuple[str, float, str]) -> RawFinding:
    offset, share, window = tz
    return _finding(
        rule="gitmeta.commit_timezone",
        family=IssueFamily.metadata_leak,
        subject=f"timezone:{repo.rel}:{offset}",
        title="Commit timestamps disclose a consistent timezone",
        description=(
            f"{share:.0%} of commits in {repo.rel} carry the UTC offset "
            f"{offset}, peaking at {window}. A stable offset and a working-"
            "hours pattern narrow the operating region without any content "
            "analysis at all."
        ),
        # Deliberately just the offset: the share moves with every commit, and
        # a fingerprint that moves loses the analyst's triage decision.
        matched=offset,
        detector=DetectorClass.heuristic,
        confidence=0.5,
        severity="MEDIUM",
        recommendation=(
            "Commit with `TZ=UTC` so timestamps carry no regional signal."
        ),
    )


# ── orchestration ─────────────────────────────────────────────────────────

def declared_terms() -> list[str]:
    """Operator-declared terms, read from the staged dirty-word list.

    The list is staged by the pipeline for the dirty-word scanner, which runs
    ahead of this one. It is read here — and never re-staged or logged —
    because history is the one place a declared operator handle can hide from
    a scanner that only walks files.
    """
    path = os.getenv(WORDLIST_ENV)
    if not path or not Path(path).exists():
        return []
    try:
        terms = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("gitmeta: unreadable dirty-word list: %s", exc)
        return []
    return [
        str(t["term"]) for t in terms
        if isinstance(t, dict) and t.get("term")
        # Idents are short; a two-character term would match everything.
        and len(str(t["term"])) >= 3
        and str(t.get("category")) in ("codename", "identity", "org", "marking", "hostname")
    ]


def scan_repository(
    binary: str, repo: GitRepo, limits: ResourceLimits, declared: list[str]
) -> tuple[list[RawFinding], bool]:
    """Analyse one repository. Returns (findings, degraded)."""
    findings: list[RawFinding] = []
    degraded = False

    config: dict[str, list[str]] = {}
    config_path = repo.git_dir / "config"
    if config_path.is_file():
        try:
            # Capped on read, not after: ingest permits a 256 MiB member, and
            # `.git/config` is as attacker-supplied as any other file here.
            with config_path.open("rb") as handle:
                config = parse_git_config(
                    handle.read(MAX_CONFIG_BYTES).decode("utf-8", "replace")
                )
        except OSError as exc:
            degraded = True
            logger.warning("gitmeta: could not read %s: %s", config_path, exc)

    log = _run_git(binary, repo, [
        "log", "--all", "--no-color", "--no-decorate", "--no-show-signature",
        f"--max-count={MAX_COMMITS}", f"--format={LOG_FORMAT}",
    ], limits)

    if log.ok:
        profile = parse_log((log.stdout or b"").decode("utf-8", "replace"))
        if log.status is AnalyzerStatus.completed_truncated:
            degraded = True
    else:
        # A repository with no commits exits zero and says nothing, so a
        # non-zero exit here is a real failure — a truncated clone, a pruned
        # object store. The config-derived findings below still stand, and the
        # coverage loss is reported rather than presented as a clean history.
        profile = HistoryProfile()
        degraded = True
        logger.info("gitmeta: log walk on %s ended %s", repo.rel, log.status.value)

    findings.append(history_present_finding(repo, profile.commits))

    identities = profile.identities + [
        ident for ident in configured_identities(config)
        if not any(
            existing.email.lower() == ident.email.lower() for existing in profile.identities
        )
    ]
    findings += identity_findings(repo, identities, declared)
    findings += remote_findings(repo, config)

    tz = timezone_profile(profile)
    if tz:
        findings.append(timezone_finding(repo, tz))

    deleted = _run_git(binary, repo, [
        "log", "--all", "--no-color", "--no-show-signature", "--diff-filter=D",
        "--name-only", "--format=", f"--max-count={MAX_DIFF_COMMITS}",
    ], limits)
    if deleted.ok:
        findings += deleted_file_findings(
            repo, parse_deleted_paths((deleted.stdout or b"").decode("utf-8", "replace"))
        )
    else:
        # Partial coverage is reported, not hidden: everything above still
        # holds, but this question went unanswered.
        degraded = True
        logger.info("gitmeta: deleted-path walk on %s ended %s", repo.rel, deleted.status.value)

    return findings, degraded


def _incomplete_reason(repos_truncated: bool, degraded: bool) -> str | None:
    if repos_truncated:
        return f"more than {MAX_REPOS} repositories; the rest were not read"
    return "history walk incomplete" if degraded else None


def run(source_root: Path, output_dir: Path, *,
        limits: ResourceLimits | None = None, **_kw) -> ScannerOutcome:
    binary = shutil.which("git")
    if not binary:
        # The one genuine coverage hole: we could not look.
        return ScannerOutcome(
            sensor=SENSOR, status=AnalyzerStatus.unavailable.value,
            reason="git not on PATH",
        )

    repos, repos_truncated = find_repositories(source_root)
    version = git_version(binary)

    if not repos:
        # A measured result, not a gap. The artifact carries no history.
        return ScannerOutcome(
            sensor=SENSOR, status=AnalyzerStatus.completed.value,
            version=version, ruleset_version="0 repositories",
            reason="no git repository in artifact",
        )

    limits = limits or DEFAULT_LIMITS
    declared = declared_terms()

    findings: list[RawFinding] = []
    degraded = repos_truncated
    for repo in repos:
        try:
            found, repo_degraded = scan_repository(binary, repo, limits, declared)
        except Exception as exc:  # one bad repository must not lose the others
            logger.warning("gitmeta: %s raised on %s", type(exc).__name__, repo.rel,
                           exc_info=True)
            degraded = True
            continue
        findings += found
        degraded = degraded or repo_degraded

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "sensor.results.jsonl").write_text(
        "\n".join(json.dumps(f.to_dict()) for f in findings)
    )

    return ScannerOutcome(
        sensor=SENSOR,
        status=(
            AnalyzerStatus.completed_truncated.value if degraded
            else AnalyzerStatus.completed.value
        ),
        findings=findings,
        version=version,
        ruleset_version=f"{len(repos)} repositor{'y' if len(repos) == 1 else 'ies'}",
        reason=_incomplete_reason(repos_truncated, degraded),
    )

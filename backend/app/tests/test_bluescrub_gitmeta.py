"""Git history metadata.

The repository that ships beside the files is a different attribution surface
from the files themselves, and the rest of the pipeline deliberately looks away
from it: ``fpfilter`` suppresses anything found under ``.git`` as tool-owned
output. These tests pin the three things that makes fragile — that gitmeta's
findings survive that filter, that an absent repository is a measured result
rather than a coverage hole, and that a repository having authors is not on its
own a disqualification.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from backend.app.bluescrub import fpfilter, redaction, service as bs_service, wordlists as wl
from backend.app.bluescrub.canonicalize import canonicalize
from backend.app.bluescrub.pillars import DetectorClass, IssueFamily, Pillar
from backend.app.bluescrub.scanners import gitmeta
from backend.app.bluescrub.scoring import ScannerRun, coverage_for
from backend.app.bluescrub.severity_table import build_rule_mapping, canonical_severity
from backend.app.database_v2 import Base
from backend.app.models.finding import Finding
from backend.app.tests._bluescrub_schemas import validator

pytestmark = pytest.mark.skipif(
    not shutil.which("git"), reason="git not installed"
)


@pytest.fixture(autouse=True)
def _no_uid_drop(monkeypatch):
    monkeypatch.setenv("AIPAM_BLUESCRUB_REQUIRE_UID_DROP", "false")
    monkeypatch.delenv(gitmeta.WORDLIST_ENV, raising=False)


@pytest.fixture()
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path/'d.db'}")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


# ── fixtures ──────────────────────────────────────────────────────────────

#: A fixed environment, so the machine running the tests cannot colour the
#: fixture: without this, the developer's own `user.email` ends up in every
#: repository the suite builds.
GIT_ENV = {
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    "HOME": "/nonexistent",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_TERMINAL_PROMPT": "0",
}


def git(repo: Path, *args: str, when: str | None = None) -> str:
    env = dict(GIT_ENV)
    if when:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = when
    return subprocess.run(
        ["git", *args], cwd=repo, env=env, check=True,
        capture_output=True, text=True,
    ).stdout


def make_repo(
    root: Path,
    *,
    author: str = "Ada Lovelace",
    email: str = "ada@redcell.internal",
    remote: str | None = None,
    commits: int = 1,
    offset: str = "+07:00",
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    git(root, "init", "-q", ".")
    git(root, "config", "user.name", author)
    git(root, "config", "user.email", email)
    if remote:
        git(root, "remote", "add", "origin", remote)
    for n in range(commits):
        (root / "main.c").write_text(f"int main(){{return {n};}}\n")
        git(root, "add", "-A")
        git(root, "commit", "-qm", f"c{n}", when=f"2024-03-{n + 1:02d}T09:15:00{offset}")
    return root


@pytest.fixture()
def job(tmp_path):
    source = tmp_path / "input" / "source"
    source.mkdir(parents=True)
    return tmp_path


def scan(job_dir: Path):
    return gitmeta.run(job_dir / "input" / "source", job_dir / "sensors" / "gitmeta")


def _rule_of(row: Finding) -> str:
    """`Finding` has no rule column; the rule id lives in the evidence blob."""
    return json.loads(row.evidence_json or "{}").get("rule_id", "")


# ── absence is a result, not a gap ────────────────────────────────────────

def test_no_repository_is_a_measured_result(job):
    """The opposite of the dirty-word scanner. A missing wordlist means the
    operator never said what to look for; a missing `.git` is a fact about the
    artifact — there is no history to leak."""
    (job / "input" / "source" / "main.c").write_text("int main(){}\n")
    outcome = scan(job)

    assert outcome.status == "completed"
    assert outcome.findings == []
    assert "no git repository" in outcome.reason


def test_absent_repository_does_not_degrade_attribution(job):
    """A clean run is coverage 1.0. Reporting `unavailable` here would mark
    every history-free artifact as only partly assessed, forever."""
    (job / "input" / "source" / "main.c").write_text("int main(){}\n")
    runs = [ScannerRun(
        sensor="gitmeta", status=scan(job).status,
        required_for=(Pillar.attribution,),
    )]
    coverage, degraded, missing = coverage_for(Pillar.attribution, runs)

    assert (coverage, degraded, missing) == (1.0, False, [])


def test_missing_git_binary_is_real_coverage_loss(job, monkeypatch):
    """Here we genuinely could not look, which is not the same as looking and
    finding nothing."""
    make_repo(job / "input" / "source")
    monkeypatch.setattr(gitmeta.shutil, "which", lambda _name: None)
    outcome = scan(job)

    assert outcome.status == "unavailable"
    coverage, _, missing = coverage_for(Pillar.attribution, [ScannerRun(
        sensor="gitmeta", status=outcome.status, required_for=(Pillar.attribution,),
    )])
    assert coverage == 0.0 and missing == ["gitmeta"]


# ── repository discovery ──────────────────────────────────────────────────

def test_finds_a_repository_at_the_artifact_root(job):
    make_repo(job / "input" / "source")
    repos, truncated = gitmeta.find_repositories(job / "input" / "source")

    assert not truncated
    assert [r.rel for r in repos] == ["."]


def test_finds_a_nested_repository(job):
    src = job / "input" / "source"
    (src / "loader").mkdir(parents=True)
    make_repo(src / "loader")
    repos, _ = gitmeta.find_repositories(src)

    assert [r.rel for r in repos] == ["loader"]


def test_gitdir_pointer_escaping_the_artifact_is_refused(job, tmp_path):
    """`.git` may be a file holding `gitdir: <path>`. The path is written by
    whoever built the archive, so following an absolute one hands git a
    directory outside the staged tree."""
    src = job / "input" / "source"
    outside = tmp_path / "outside.git"
    outside.mkdir()
    (src / ".git").write_text(f"gitdir: {outside}\n")

    assert gitmeta.resolve_gitdir_file(src / ".git", src) is None
    assert gitmeta.find_repositories(src) == ([], False)


def test_gitdir_pointer_inside_the_artifact_is_followed(job):
    src = job / "input" / "source"
    real = src / "store" / "modules" / "loader"
    real.mkdir(parents=True)
    (real / "HEAD").write_text("ref: refs/heads/main\n")
    (src / "sub").mkdir()
    (src / "sub" / ".git").write_text(f"gitdir: {real}\n")

    assert gitmeta.resolve_gitdir_file(src / "sub" / ".git", src) == real.resolve()


def test_symlinked_gitdir_is_skipped(job, tmp_path):
    src = job / "input" / "source"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (src / ".git").symlink_to(elsewhere, target_is_directory=True)

    assert gitmeta.find_repositories(src) == ([], False)


def test_repository_count_is_bounded_and_says_so(job):
    src = job / "input" / "source"
    for n in range(4):
        (src / f"m{n}").mkdir(parents=True)
        (src / f"m{n}" / ".git").mkdir()
    repos, truncated = gitmeta.find_repositories(src, limit=2)

    assert len(repos) == 2 and truncated


def test_an_empty_repository_is_still_reported_and_is_not_degraded(job):
    """A repository with no commits exits zero and says nothing, so it must not
    be classified with the truncated clones."""
    src = job / "input" / "source"
    src.mkdir(parents=True, exist_ok=True)
    git(src, "init", "-q", ".")
    outcome = scan(job)

    assert outcome.status == "completed"
    assert [f.rule_id for f in outcome.findings] == ["gitmeta.history_present"]


def test_a_broken_object_store_degrades_rather_than_reporting_a_clean_history(job):
    """The alternative is a repository whose history could not be read showing
    up as a repository with nothing in its history."""
    src = job / "input" / "source"
    make_repo(src, commits=2)
    for obj in (src / ".git" / "objects").iterdir():
        if obj.is_dir():
            for blob in obj.iterdir():
                blob.unlink()
    outcome = scan(job)

    assert outcome.status == "completed_truncated"
    assert "incomplete" in outcome.reason
    # The repository itself is a filesystem fact and is reported regardless.
    assert any(f.rule_id == "gitmeta.history_present" for f in outcome.findings)


# ── the repository's own config is evidence, not configuration ────────────

def test_argv_neutralises_the_config_keys_that_name_programs(job):
    """`.git/config` is attacker-authored and several of its keys name binaries
    git will execute. Repo-local config cannot be disabled, so each one is
    overridden on the command line, where `-c` outranks the repository."""
    make_repo(job / "input" / "source")
    repo = gitmeta.find_repositories(job / "input" / "source")[0][0]
    argv = gitmeta.git_argv("/usr/bin/git", repo, "log")

    settings = {argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "-c"}
    for key in ("core.pager", "core.fsmonitor", "core.sshCommand",
                "core.alternateRefsCommand", "log.showSignature", "diff.external"):
        assert any(s.startswith(f"{key}=") for s in settings), key
    assert "--no-pager" in argv


def test_argv_permits_the_repository_despite_foreign_ownership(job):
    """The analyzer drops to a dedicated account, so the staged tree belongs to
    somebody else and git refuses it as "dubious ownership" before running."""
    make_repo(job / "input" / "source")
    repo = gitmeta.find_repositories(job / "input" / "source")[0][0]
    argv = gitmeta.git_argv("/usr/bin/git", repo, "log")

    assert f"safe.directory={repo.git_dir}" in argv


def test_no_network_capable_subcommand_is_ever_issued(job, monkeypatch):
    """The isolation contract requires network verification to be *hard*
    disabled for the repo_history class — asserted here, not configured."""
    make_repo(job / "input" / "source", remote="https://git.internal/ops/x.git")
    seen: list[list[str]] = []
    real = gitmeta.run_analyzer

    def _record(argv, **kwargs):
        seen.append(argv)
        return real(argv, **kwargs)

    monkeypatch.setattr(gitmeta, "run_analyzer", _record)
    scan(job)

    assert seen, "no git invocation captured"
    for argv in seen:
        words = set(argv)
        assert not (words & gitmeta.NETWORK_SUBCOMMANDS), argv
        assert "protocol.allow=never" in argv or argv[1:] == ["--version"]


def test_the_hosts_own_git_config_cannot_colour_the_result(job, monkeypatch):
    """Without this the analyst's `user.email` from ~/.gitconfig would show up
    as a finding about somebody else's artifact."""
    captured: dict = {}

    def _record(argv, **kwargs):
        captured.update(kwargs.get("env_extra") or {})
        raise RuntimeError("stop here")

    make_repo(job / "input" / "source")
    monkeypatch.setattr(gitmeta, "run_analyzer", _record)
    with pytest.raises(RuntimeError):
        gitmeta.git_version("/usr/bin/git")

    assert captured["GIT_CONFIG_NOSYSTEM"] == "1"
    assert captured["GIT_CONFIG_GLOBAL"] == "/dev/null"


# ── pure parsers ──────────────────────────────────────────────────────────

def test_parse_log_separates_author_from_committer():
    sep = gitmeta.FIELD_SEP
    text = "\n".join([
        sep.join(["Ada", "ada@x.internal", "Bob", "bob@x.internal",
                  "2024-03-01T09:15:00+07:00", "2024-03-01T09:15:00+07:00"]),
        sep.join(["Ada", "ada@x.internal", "Ada", "ada@x.internal",
                  "2024-03-02T10:15:00+07:00", "2024-03-02T10:15:00+07:00"]),
    ])
    profile = gitmeta.parse_log(text)

    assert profile.commits == 2
    by_email = {i.email: i for i in profile.identities}
    assert by_email["ada@x.internal"].roles == {"author", "committer"}
    assert by_email["bob@x.internal"].roles == {"committer"}


def test_a_malformed_record_is_counted_not_fatal():
    """One corrupt line must not cost us the rest of the history."""
    sep = gitmeta.FIELD_SEP
    good = sep.join(["Ada", "a@x", "Ada", "a@x", "2024-03-01T09:00:00+00:00",
                     "2024-03-01T09:00:00+00:00"])
    profile = gitmeta.parse_log(f"garbage\n{good}\n")

    assert profile.commits == 1 and profile.malformed == 1


def test_git_config_is_parsed_with_its_tab_indentation():
    """`configparser` reads git's tab-indented entries as continuations of the
    previous value and returns nonsense without raising."""
    text = (
        '[remote "origin"]\n'
        "\turl = https://git.internal/ops/loader.git\n"
        "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
        "[user]\n"
        "\temail = ada@redcell.internal\n"
    )
    config = gitmeta.parse_git_config(text)

    assert config["remote.origin.url"] == ["https://git.internal/ops/loader.git"]
    assert config["user.email"] == ["ada@redcell.internal"]


@pytest.mark.parametrize("url,sanitised,credential", [
    ("https://ada:ghp_secret@git.internal/x.git",
     "https://git.internal/x.git", "ada:ghp_secret"),
    # A GitHub token is bare userinfo with no colon, so a rule that only took
    # the part after a colon would write the token back out as a username.
    ("https://ghp_secrettokenvalue@github.com/o/r.git",
     "https://github.com/o/r.git", "ghp_secrettokenvalue"),
    # A bare ssh login name is not a secret, so it stays as evidence.
    ("git@github.com:org/repo.git", "git@github.com:org/repo.git", None),
    ("deploy:hunter2@host.internal:ops/x.git", "host.internal:ops/x.git",
     "deploy:hunter2"),
    ("https://github.com/org/repo.git", "https://github.com/org/repo.git", None),
])
def test_remote_userinfo_is_stripped_whole(url, sanitised, credential):
    assert gitmeta.split_remote_credentials(url) == (sanitised, credential)


@pytest.mark.parametrize("url,host", [
    ("https://git.redcell.internal/ops/x.git", "git.redcell.internal"),
    ("git@github.com:org/repo.git", "github.com"),
    ("ssh://git@gitlab.internal:2222/o/r.git", "gitlab.internal"),
    ("/srv/local/mirror.git", None),
    ("file:///srv/mirror.git", None),
])
def test_host_of_handles_every_remote_form(url, host):
    assert gitmeta.host_of(url) == host


@pytest.mark.parametrize("host,public", [
    ("github.com", True), ("gist.github.com", True),
    ("git.redcell.internal", False), ("notgithub.com", False),
])
def test_public_forge_recognition(host, public):
    assert gitmeta.is_public_forge(host) is public


@pytest.mark.parametrize("path,sensitive", [
    ("config/.env", True), ("keys/id_rsa", True), ("tls/server.pem", True),
    ("ops/terraform.tfvars", True), ("dump/prod_credentials.txt", True),
    # The name is all the evidence there is, so a source file *about* secrets
    # must not be read as one.
    ("app/secrets.py", False), ("docs/passwords.md", False),
    ("src/main.c", False), ("README", False),
])
def test_deleted_path_heuristic(path, sensitive):
    assert gitmeta.is_sensitive_path(path) is sensitive


def test_timezone_needs_both_volume_and_dominance():
    def profile(offsets):
        p = gitmeta.HistoryProfile()
        p.commits = len(offsets)
        for o in offsets:
            p.offsets[o] += 1
            p.hours[9] += 1
        return p

    assert gitmeta.timezone_profile(profile(["+07:00"] * 5)) is None, "too few commits"
    # UTC is both the correct normalisation and a real region, so it says
    # nothing either way.
    assert gitmeta.timezone_profile(profile(["+00:00"] * 20)) is None
    mixed = ["+07:00"] * 10 + ["+01:00"] * 10
    assert gitmeta.timezone_profile(profile(mixed)) is None, "no dominant offset"

    result = gitmeta.timezone_profile(profile(["+07:00"] * 19 + ["+01:00"]))
    assert result and result[0] == "+07:00"


# ── findings must survive the filter that hides `.git` ────────────────────

def test_no_finding_carries_a_path_inside_dot_git(job):
    """`fpfilter` drops anything under `.git` as tool-owned output — right for
    a scanner walking blobs, and it would delete this module's entire output."""
    make_repo(job / "input" / "source", remote="https://git.internal/ops/x.git",
              commits=2)
    findings = scan(job).findings

    assert findings
    for finding in findings:
        assert finding.location.kind == "project"
        # The filter matches whole path components, so `x.git` at the end of a
        # remote URL is fine and a `.git/` segment is not.
        path = finding.location.file or finding.location.subject
        assert ".git" not in fpfilter._segments(path), path


def test_findings_survive_false_positive_suppression(job):
    make_repo(job / "input" / "source", remote="https://git.internal/ops/x.git",
              commits=2)
    findings = scan(job).findings
    result = fpfilter.apply(list(findings))

    assert len(result.kept) == len(findings), result.by_filter


def test_findings_validate_against_the_raw_contract(job):
    make_repo(job / "input" / "source",
              remote="https://ada:ghp_secrettoken@git.internal/ops/x.git", commits=12)
    check = validator("raw-finding.schema.json")
    for finding in scan(job).findings:
        check.validate(finding.to_dict())


# ── severity calibration ──────────────────────────────────────────────────

def test_an_author_identity_is_serious_but_not_disqualifying():
    """A repository has authors by definition. Treating each one as critical
    would fail every artifact that shipped its history, a vendored open-source
    tree included — and disqualification has to mean something."""
    assert canonical_severity(
        "gitmeta.author_identity", IssueFamily.attribution_identity,
        DetectorClass.ast_pattern,
    ) == "high"


def test_a_declared_identity_is_disqualifying():
    """The dirty-word argument: nothing here is more precise than being told."""
    assert canonical_severity(
        "gitmeta.declared_identity", IssueFamily.attribution_identity,
        DetectorClass.ast_pattern,
    ) == "critical"


def test_history_present_outranks_its_family_default():
    assert canonical_severity(
        "gitmeta.history_present", IssueFamily.metadata_leak, DetectorClass.ast_pattern,
    ) == "high"


def test_contributors_alone_do_not_disqualify_an_artifact(job):
    """The end of the calibration argument, measured rather than asserted."""
    make_repo(job / "input" / "source", author="Upstream Maintainer",
              email="maint@opensource.example.org", commits=3)
    findings = scan(job).findings
    groups = canonicalize(findings, project_id="p",
                          rule_mapping=build_rule_mapping(findings)).groups

    assert groups
    assert not [g for g in groups
                if g.pillar is Pillar.attribution and g.severity == "critical"]


# ── evidence handling ─────────────────────────────────────────────────────

def test_a_remote_token_never_reaches_the_url_finding(job):
    make_repo(job / "input" / "source",
              remote="https://ada:ghp_secrettokenvalue@git.internal/ops/x.git")
    findings = scan(job).findings
    url = next(f for f in findings if f.rule_id == "gitmeta.remote_url")

    assert "ghp_secrettokenvalue" not in json.dumps(url.to_dict())
    assert url.matched_tokens == "https://git.internal/ops/x.git"


def test_the_token_is_masked_and_fingerprinted_by_central_redaction(job, monkeypatch):
    """It is carried on exactly one finding, in the family the redaction stage
    knows to mask — rather than being scrubbed here, where a future adapter
    could forget to."""
    monkeypatch.setenv(redaction.KEY_ENV, "test-key")
    make_repo(job / "input" / "source",
              remote="https://ada:ghp_secrettokenvalue@git.internal/ops/x.git")

    redacted = redaction.redact(list(scan(job).findings))
    blob = json.dumps([f.to_dict() for f in redacted.findings])

    assert "ghp_secrettokenvalue" not in blob
    secret = next(f.secret for f in redacted.findings
                  if f.rule_id == "gitmeta.remote_credentials")
    assert secret.fingerprint.startswith("hmac-sha256:")


def test_a_shipped_pack_term_inside_an_ident_is_decisive():
    """The packs already declare `.internal` sensitive, so an ident on an
    internal domain is a declared leak rather than an unknown contributor —
    which is the whole reason gitmeta reads the staged wordlist at all."""
    repo = gitmeta.GitRepo(Path("/s"), Path("/s/.git"), ".")
    identity = gitmeta.Identity(name="Ada", email="ada@redcell.internal", commits=1)

    findings = gitmeta.identity_findings(repo, [identity], [".internal"])
    assert [f.rule_id for f in findings] == ["gitmeta.declared_identity"]

    plain = gitmeta.identity_findings(repo, [identity], ["NIGHTFALL"])
    assert [f.rule_id for f in plain] == ["gitmeta.author_identity"]


def test_a_forge_noreply_address_is_a_handle_not_an_anonymisation():
    """`12345+alice@users.noreply.github.com` hides the mailbox and publishes
    the account name, which is the identity either way."""
    assert gitmeta.is_forge_handle("12345+alice@users.noreply.github.com")
    assert not gitmeta.is_forge_handle("ada@redcell.internal")


def test_gits_synthesised_ident_is_a_leak_not_a_placeholder():
    """With `user.email` unset git invents `user@hostname.(none)`, which looks
    like a placeholder and carries both an account and a machine name."""
    assert gitmeta.is_synthesised_ident("root@build-vm-04.(none)")
    assert not gitmeta.is_synthesised_ident("ada@redcell.internal")


def test_identity_configured_but_never_committed_is_still_found(job):
    """A repository with no commits still names whoever set it up."""
    src = job / "input" / "source"
    src.mkdir(parents=True, exist_ok=True)
    git(src, "init", "-q", ".")
    git(src, "config", "user.email", "ada@redcell.internal")

    identities = [f for f in scan(job).findings
                  if f.rule_id.endswith("_identity")]
    assert any("ada@redcell.internal" in (f.matched_tokens or "") for f in identities)


# ── fingerprints must not move under the analyst ──────────────────────────

def test_committing_does_not_orphan_existing_triage(job):
    """`history_present` and `commit_timezone` describe the repository, not a
    commit. If their evidence carried counts or percentages, every new commit
    would re-key them and reset whatever the analyst had decided."""
    src = job / "input" / "source"
    make_repo(src, commits=12)

    def ids():
        findings = scan(job).findings
        groups = canonicalize(findings, project_id="p").groups
        return {g.primary_rule_id: g.canonical_id for g in groups}

    before = ids()
    (src / "extra.c").write_text("int extra(){return 1;}\n")
    git(src, "add", "-A")
    git(src, "commit", "-qm", "more", when="2024-04-01T09:15:00+07:00")
    after = ids()

    for rule in ("gitmeta.history_present", "gitmeta.commit_timezone"):
        assert before[rule] == after[rule], rule


def test_two_identities_stay_two_findings(job):
    src = job / "input" / "source"
    make_repo(src, author="Ada", email="ada@redcell.internal")
    git(src, "config", "user.email", "bob@redcell.internal")
    git(src, "config", "user.name", "Bob")
    (src / "b.c").write_text("int b(){return 0;}\n")
    git(src, "add", "-A")
    git(src, "commit", "-qm", "b", when="2024-03-09T09:15:00+07:00")

    findings = scan(job).findings
    groups = canonicalize(findings, project_id="p").groups
    identities = [g for g in groups if g.primary_rule_id.endswith("_identity")]

    assert len(identities) == 2


# ── end to end ────────────────────────────────────────────────────────────

def test_a_declared_operator_handle_in_history_disqualifies(db, job):
    """The case the file scanners cannot reach. dirty-word walks files, and its
    own hit inside `.git` is suppressed as tool-owned output — so without
    gitmeta a leaked handle in the commit ident ships unreported."""
    wl.create(db, "Engagement", [{"term": "NIGHTFALL", "category": "codename"}])
    make_repo(job / "input" / "source", author="Ada Nightfall",
              email="ada@corp.example.org", commits=2)

    dacv = bs_service.analyze_and_persist(db, "j", job, profile="triage")["dacv"]

    rows = db.scalars(select(Finding).where(Finding.sensor == "gitmeta")).all()
    declared = [r for r in rows if _rule_of(r) == "gitmeta.declared_identity"]
    assert declared, [_rule_of(r) for r in rows]
    assert all(r.severity == "critical" for r in declared)
    assert dacv["disqualified"] is True
    assert dacv["scoped"]["grade"] == "F"


def test_a_scan_of_an_ordinary_repository_persists_without_disqualifying(db, job):
    wl.create(db, "Engagement", [{"term": "NIGHTFALL", "category": "codename"}])
    make_repo(job / "input" / "source", author="Upstream Maintainer",
              email="maint@opensource.example.org",
              remote="https://github.com/upstream/loader.git", commits=3)

    dacv = bs_service.analyze_and_persist(db, "j", job, profile="triage")["dacv"]

    rules = {_rule_of(r) for r in db.scalars(
        select(Finding).where(Finding.sensor == "gitmeta")
    ).all()}
    assert "gitmeta.history_present" in rules
    assert "gitmeta.author_identity" in rules
    assert "gitmeta.remote_url" in rules
    assert dacv["disqualified"] is False


def test_no_remote_credential_reaches_the_database(db, job, monkeypatch):
    monkeypatch.setenv(redaction.KEY_ENV, "test-key")
    make_repo(job / "input" / "source",
              remote="https://ada:ghp_secrettokenvalue@git.internal/ops/x.git",
              commits=2)

    bs_service.analyze_and_persist(db, "j", job, profile="triage")

    dumped = json.dumps([
        {c.name: str(getattr(row, c.name)) for c in Finding.__table__.columns}
        for row in db.scalars(select(Finding)).all()
    ])
    assert "ghp_secrettokenvalue" not in dumped


def test_gitmeta_is_enabled_wherever_attribution_is_in_scope():
    """The isolation contract's rule for the repo_history class."""
    from backend.app.bluescrub.registry import pillars_in_scope, required_for

    for profile in ("triage", "standard", "deep"):
        assert Pillar.attribution in pillars_in_scope(profile)
        assert "gitmeta" in required_for(Pillar.attribution, profile)

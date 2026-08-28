"""Network indicators compiled into an artifact.

The gap this closes was found by running the pipeline against its intended
subject for the first time: a stripped implant with `10.20.30.40:8443` compiled
into it produced zero Co-Optability findings. The capability was never missing
— the vendored binary analyzer extracts addresses with regex over bytes and no
third-party library — but it sits behind
`REQUIRED_CAPABILITIES = ("pe_analysis", "elf_analysis")` and went dark on any
host without them.

What is pinned here is mostly *precision*, because an IP regex over binary
strings is the exact shape that once produced 344 criticals from a two-letter
substring. The rules that shipped were measured against six unrelated system
binaries first; the rules that did not ship are recorded as tests too.
"""

import ipaddress
import shutil
import subprocess
from pathlib import Path

import pytest

from backend.app.bluescrub import binstrings
from backend.app.bluescrub.pillars import IssueFamily, Pillar
from backend.app.bluescrub.scanners import binary_indicators as bi
from backend.app.tests._bluescrub_schemas import validator


def elf_with(payload: bytes, *, pad: int = 512) -> bytes:
    return b"\x7fELF\x02\x01\x01" + b"\x00" * (pad - 7) + payload + b"\x00" * 64


# ── the case the detector exists for ──────────────────────────────────────

def test_an_address_surrounded_by_binary_junk_is_found():
    """The C2 in the fixture is recovered as `........10.20.30.40:8443`. A
    lookbehind excluding a preceding dot silently dropped it — the detector
    reported nothing and looked like it was working."""
    found = bi.extract_indicators("........10.20.30.40:8443")

    assert [i.value for i in found] == ["10.20.30.40"]


def test_the_offset_points_at_the_first_octet_not_the_junk():
    found = bi.extract_indicators("....10.20.30.40:8443", base_offset=1000)
    assert found[0].offset == 1004


def test_a_wide_string_offset_counts_two_bytes_per_character():
    found = bi.extract_indicators("ab10.20.30.40", base_offset=2048, width=2)
    assert found[0].offset == 2048 + 2 * 2


# ── precision: what must not fire ─────────────────────────────────────────

@pytest.mark.parametrize("text", [
    "lib 1.2.3.4.5 build",          # five parts — a version string
    "version 1.2.3",                # three parts
    "1.2.3.4.5.6",
])
def test_a_version_string_is_not_an_address(text):
    """Examining the whole dotted run is what separates these. A lookaround
    cannot: `1.2.3.4.5` contains a perfectly well-formed quad."""
    assert bi.extract_indicators(text) == []


@pytest.mark.parametrize("address", [
    "127.0.0.1", "0.0.0.0", "255.255.255.255", "169.254.1.1",
    "224.0.0.1", "192.0.2.15", "198.51.100.7", "203.0.113.9", "0.2.4.6",
])
def test_reserved_and_documentation_addresses_are_not_c2s(address):
    assert bi.is_reportable_address(address) is False


@pytest.mark.parametrize("address", ["10.20.30.40", "192.168.1.5",
                                     "172.16.0.9", "45.33.32.156"])
def test_private_space_is_reported(address):
    """`10.20.30.40` in a shipped implant is exactly the finding, and an
    internal address additionally says where the thing was built or aimed."""
    assert bi.is_reportable_address(address) is True
    assert ipaddress.IPv4Address(address) is not None


def test_octets_over_255_are_not_addresses():
    assert bi.extract_indicators("999.888.777.666") == []


@pytest.mark.skipif(not Path("/bin/ls").exists(), reason="no system binaries")
def test_ordinary_system_binaries_stay_quiet():
    """The measurement the shipped rules were chosen on. Across six unrelated
    binaries the only hits are genuine IP literals from CPython's own
    documentation — so the rule earns its place instead of matching everything
    the way a bare `\\d+\\.\\d+\\.\\d+\\.\\d+` would."""
    noisy = []
    for path in ("/bin/ls", "/bin/bash", "/usr/bin/git",
                 "/usr/lib/x86_64-linux-gnu/libc.so.6"):
        target = Path(path)
        if not target.exists():
            continue
        text = "\n".join(s.value for s in binstrings.recover(target).strings)
        hits = bi.extract_indicators(text)
        if hits:
            noisy.append((path, [i.value for i in hits]))

    assert noisy == [], f"false positives on ordinary binaries: {noisy}"


# ── internal hosts ────────────────────────────────────────────────────────

@pytest.mark.parametrize("text,expected", [
    ("cdn-update.redcell-ops.internal", "cdn-update.redcell-ops.internal"),
    ("a.chen@redcell-ops.internal", "redcell-ops.internal"),
    ("build01.corp", "build01.corp"),
    ("nas.lan", "nas.lan"),
])
def test_internal_namespaces_are_reported(text, expected):
    hosts = [i.value for i in bi.extract_indicators(text) if i.kind == "internal_host"]
    assert expected in hosts


@pytest.mark.parametrize("text", [
    "thread.local", "Setup.local", "instaweb.local",
    "https://www.gnu.org/licenses/", "python.org", "mitre.org",
])
def test_public_and_mdns_names_are_not_reported(text):
    """Measured: general domains in binaries are licence and bug-tracker
    boilerplate — gnu.org, python.org, launchpad.net — and `.local` is mDNS and
    string-boundary noise. An allowlist to separate a real host from those
    would be endless, so only namespaces with nothing to separate are used."""
    assert [i for i in bi.extract_indicators(text) if i.kind == "internal_host"] == []


# ── finding shape ─────────────────────────────────────────────────────────

def test_an_address_is_co_optability_and_a_host_is_attribution():
    """The pillars answer different questions: who could take this over, and
    who does it point back to."""
    recovery = binstrings.Recovery(sha256="a" * 64, binary_format="elf")
    findings = bi.to_findings([
        {"file": "loader", "value": "10.20.30.40", "kind": "ipv4",
         "offset": 16, "sha256": "a" * 64, "format": "elf"},
        {"file": "loader", "value": "build01.corp", "kind": "internal_host",
         "offset": 32, "sha256": "a" * 64, "format": "elf"},
    ])
    assert recovery.sha256
    by_family = {f.issue_family: f for f in findings}
    assert by_family[IssueFamily.hardcoded_c2].pillar_hint is Pillar.co_optability
    assert (by_family[IssueFamily.attribution_infrastructure].pillar_hint
            is Pillar.attribution)


def test_findings_validate_against_the_raw_contract():
    check = validator("raw-finding.schema.json")
    for finding in bi.to_findings([
        {"file": "loader", "value": "10.20.30.40", "kind": "ipv4",
         "offset": 16, "sha256": "b" * 64, "format": "elf"},
        {"file": "loader", "value": "nas.lan", "kind": "internal_host",
         "offset": None, "sha256": "b" * 64, "format": None},
    ]):
        check.validate(finding.to_dict())


def test_an_address_is_an_observable_for_the_ioc_bridge():
    """Unlike a build path, an address has defined equality — it can be
    correlated with what the traffic pipeline saw."""
    finding = bi.to_findings([
        {"file": "loader", "value": "10.20.30.40", "kind": "ipv4",
         "offset": 0, "sha256": "c" * 64, "format": "elf"}])[0]

    assert [(o.type, o.value, o.origin) for o in finding.observables] == [
        ("ip", "10.20.30.40", "recovered_string")]


def test_a_record_without_a_digest_is_dropped_not_forged():
    assert bi.to_findings([{"file": "x", "value": "10.20.30.40",
                            "kind": "ipv4", "sha256": ""}]) == []


def test_a_private_address_says_so_in_the_description():
    finding = bi.to_findings([
        {"file": "loader", "value": "10.20.30.40", "kind": "ipv4",
         "offset": 0, "sha256": "d" * 64, "format": "elf"}])[0]
    public = bi.to_findings([
        {"file": "loader", "value": "45.33.32.156", "kind": "ipv4",
         "offset": 0, "sha256": "d" * 64, "format": "elf"}])[0]

    assert "private space" in finding.description
    assert "private space" not in public.description


def test_a_giant_blob_is_not_scanned():
    assert bi.extract_indicators("1" * (bi.MAX_STRING_LENGTH + 1)) == []


# ── isolation and registration ────────────────────────────────────────────

def test_the_scan_runs_behind_a_process_boundary(tmp_path, monkeypatch):
    captured = {}

    def _record(argv, **_kw):
        captured["argv"] = argv
        raise RuntimeError("stop here")

    monkeypatch.setattr(bi, "run_analyzer", _record)
    with pytest.raises(RuntimeError):
        bi.run(tmp_path, tmp_path / "out")

    assert "backend.app.bluescrub.isolation.analyzer_main" in captured["argv"]
    assert "binary_indicators" in captured["argv"]


def test_it_needs_no_third_party_library():
    """The whole point: the vendored analyzer can do this too, and is switched
    off on a host without pefile/pyelftools — libraries this never uses."""
    import ast

    import backend.app.bluescrub.scanners.binary_indicators as module

    tree = ast.parse(Path(module.__file__).read_text())
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    assert not imported & {"pefile", "elftools", "capstone", "lief"}, imported


def test_it_is_required_for_co_optability():
    from backend.app.bluescrub.registry import required_for

    assert "binary_indicators" in required_for(Pillar.co_optability, "standard")


@pytest.mark.skipif(not shutil.which("gcc"), reason="no compiler")
def test_end_to_end_on_a_compiled_artifact(tmp_path):
    src = tmp_path / "t.c"
    src.write_text(
        'const char *a = "10.20.30.40:8443";\n'
        'const char *h = "cdn.redcell-ops.internal";\n'
        "int main(void){return 0;}\n"
    )
    subprocess.run(["gcc", "-O2", "-s", "-o", str(tmp_path / "agent"), str(src)],
                   check=True, capture_output=True)
    src.unlink()

    findings = bi.scan(tmp_path)
    values = {f.matched_tokens for f in findings}
    assert "10.20.30.40" in values
    assert "cdn.redcell-ops.internal" in values

    data = (tmp_path / "agent").read_bytes()
    address = next(f for f in findings if f.matched_tokens == "10.20.30.40")
    at = address.location.offset
    assert data[at:at + 11] == b"10.20.30.40", "the offset is not seekable"

"""BlueScrub ingest safety — hostile archives must be rejected, not sanitised.

Covers plan §15 acceptance #8: malicious archives (nested decompression, hard
links, device files, Unicode path collisions, symlink escapes) are rejected.
"""

import io
import os
import tarfile
import zipfile
from pathlib import Path

import pytest

from backend.app.bluescrub.ingest import (
    IngestError,
    IngestLimits,
    stage_archive,
)


def _tar_with(members, tmp_path: Path, name: str = "hostile.tar.gz") -> Path:
    """Build a tar.gz from (TarInfo, payload-bytes-or-None) pairs."""
    archive = tmp_path / name
    with tarfile.open(archive, "w:gz") as tf:
        for info, payload in members:
            tf.addfile(info, io.BytesIO(payload) if payload is not None else None)
    return archive


def _regular(name: str, data: bytes) -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.type = tarfile.REGTYPE
    return info, data


def test_benign_tar_stages(tmp_path):
    archive = _tar_with(
        [_regular("src/main.c", b"int main(){}"), _regular("README.md", b"# tool")],
        tmp_path,
    )
    result = stage_archive(archive, tmp_path / "out")

    assert result.file_count == 2
    assert (tmp_path / "out" / "src" / "main.c").read_bytes() == b"int main(){}"


def test_benign_zip_stages(tmp_path):
    archive = tmp_path / "ok.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("pkg/mod.py", "x = 1\n")
    result = stage_archive(archive, tmp_path / "out")

    assert result.file_count == 1
    assert (tmp_path / "out" / "pkg" / "mod.py").exists()


@pytest.mark.parametrize("member_name", ["../escape.txt", "a/../../escape.txt"])
def test_path_traversal_rejected(tmp_path, member_name):
    archive = _tar_with([_regular(member_name, b"pwn")], tmp_path)
    with pytest.raises(IngestError) as exc:
        stage_archive(archive, tmp_path / "out")
    assert exc.value.reason == "path_traversal"


def test_absolute_path_rejected(tmp_path):
    archive = _tar_with([_regular("/etc/passwd", b"pwn")], tmp_path)
    with pytest.raises(IngestError) as exc:
        stage_archive(archive, tmp_path / "out")
    # tarfile normalises a leading slash away on write, so either guard is correct.
    assert exc.value.reason in ("absolute_path", "path_traversal")


def test_symlink_member_rejected(tmp_path):
    info = tarfile.TarInfo("link")
    info.type = tarfile.SYMTYPE
    info.linkname = "/etc/passwd"
    archive = _tar_with([(info, None)], tmp_path)

    with pytest.raises(IngestError) as exc:
        stage_archive(archive, tmp_path / "out")
    assert exc.value.reason == "link_member"


def test_hard_link_member_rejected(tmp_path):
    real, _ = _regular("real.txt", b"data")
    link = tarfile.TarInfo("hard")
    link.type = tarfile.LNKTYPE
    link.linkname = "real.txt"
    archive = _tar_with([(real, b"data"), (link, None)], tmp_path)

    with pytest.raises(IngestError) as exc:
        stage_archive(archive, tmp_path / "out")
    assert exc.value.reason == "link_member"


def test_device_member_rejected(tmp_path):
    info = tarfile.TarInfo("dev/zero")
    info.type = tarfile.CHRTYPE
    info.devmajor, info.devminor = 1, 5
    archive = _tar_with([(info, None)], tmp_path)

    with pytest.raises(IngestError) as exc:
        stage_archive(archive, tmp_path / "out")
    assert exc.value.reason == "device_member"


def test_unicode_path_collision_rejected(tmp_path):
    # U+00E9 vs e + U+0301 — different bytes, same NFC form.
    archive = _tar_with(
        [_regular("café.py", b"a"), _regular("café.py", b"b")],
        tmp_path,
    )
    with pytest.raises(IngestError) as exc:
        stage_archive(archive, tmp_path / "out")
    assert exc.value.reason == "unicode_path_collision"


def test_file_count_ceiling(tmp_path):
    members = [_regular(f"f{i}.txt", b"x") for i in range(20)]
    archive = _tar_with(members, tmp_path)

    with pytest.raises(IngestError) as exc:
        stage_archive(archive, tmp_path / "out", IngestLimits(max_files=5))
    assert exc.value.reason == "too_many_files"


def test_total_size_ceiling(tmp_path):
    archive = _tar_with([_regular("big.bin", b"A" * 5000)], tmp_path)

    with pytest.raises(IngestError) as exc:
        stage_archive(archive, tmp_path / "out", IngestLimits(max_total_bytes=1000))
    assert exc.value.reason in ("member_too_large", "total_size_exceeded")


def test_zip_bomb_ratio_rejected(tmp_path):
    """A highly compressible payload trips the ratio guard before it is written."""
    archive = tmp_path / "bomb.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bomb.txt", "0" * (2 * 1024 * 1024))

    with pytest.raises(IngestError) as exc:
        stage_archive(archive, tmp_path / "out", IngestLimits(max_ratio=50))
    assert exc.value.reason == "compression_ratio"


def test_nested_archive_staged_not_extracted(tmp_path):
    """Nested archives are recorded as files. Never recursively extracted."""
    inner = tmp_path / "inner.zip"
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("deep.txt", "payload")

    archive = _tar_with([_regular("vendor/inner.zip", inner.read_bytes())], tmp_path)
    result = stage_archive(archive, tmp_path / "out")

    assert result.nested_archives == ["vendor/inner.zip"]
    assert (tmp_path / "out" / "vendor" / "inner.zip").is_file()
    assert not (tmp_path / "out" / "vendor" / "deep.txt").exists()


def test_partial_output_removed_on_rejection(tmp_path):
    """A half-extracted hostile archive is worse than none."""
    bad = tarfile.TarInfo("evil")
    bad.type = tarfile.SYMTYPE
    bad.linkname = "/etc/shadow"
    archive = _tar_with([_regular("good.txt", b"ok"), (bad, None)], tmp_path)

    out = tmp_path / "out"
    with pytest.raises(IngestError):
        stage_archive(archive, out)
    assert not out.exists()


def test_empty_archive_rejected(tmp_path):
    archive = tmp_path / "empty.tar.gz"
    with tarfile.open(archive, "w:gz"):
        pass
    with pytest.raises(IngestError) as exc:
        stage_archive(archive, tmp_path / "out")
    assert exc.value.reason == "empty_archive"


def test_corrupt_archive_rejected(tmp_path):
    archive = tmp_path / "corrupt.zip"
    archive.write_bytes(b"PK\x03\x04 not really a zip")
    with pytest.raises(IngestError) as exc:
        stage_archive(archive, tmp_path / "out")
    assert exc.value.reason == "corrupt_archive"


def test_staged_files_are_owner_only(tmp_path):
    archive = _tar_with([_regular("src/x.py", b"pass")], tmp_path)
    stage_archive(archive, tmp_path / "out")
    mode = os.stat(tmp_path / "out" / "src" / "x.py").st_mode & 0o777
    assert mode == 0o600

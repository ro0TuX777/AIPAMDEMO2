"""Hardened staging of untrusted code artifacts.

``bundle_stager`` handles telemetry archives from trusted-ish operators and
sanitises member names. That is not sufficient here: BlueScrub archives are
authored by whoever wrote the offensive tooling, so this module *rejects*
hostile archives rather than quietly rewriting them. A traversal entry is a
signal, not a formatting problem, and silently relocating it would also corrupt
the source layout that fingerprints depend on.

Nested archives are never recursively extracted — they are staged as ordinary
files. That removes the decompression-bomb class entirely rather than trying to
bound it.

Reference: docs/BLUESCRUB_DATA_HANDLING_POLICY.md, plan §14 Sprint 1 task 1.4.
"""

from __future__ import annotations

import logging
import shutil
import tarfile
import unicodedata
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

logger = logging.getLogger(__name__)

ARCHIVE_SUFFIXES = (".zip", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")


class IngestError(ValueError):
    """Rejected artifact. ``reason`` is a stable machine-readable code."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass(frozen=True)
class IngestLimits:
    """Extraction ceilings. Defaults mirror the AIPAM_BLUESCRUB_* settings."""

    max_files: int = 50_000
    max_total_bytes: int = 2 * 1024**3        # 2 GiB uncompressed
    max_file_bytes: int = 256 * 1024**2       # 256 MiB per member
    max_ratio: float = 200.0                  # uncompressed / compressed
    max_depth: int = 32                       # path components
    max_name_bytes: int = 255                 # per path component


@dataclass
class IngestResult:
    root: Path
    file_count: int = 0
    total_bytes: int = 0
    nested_archives: list[str] = field(default_factory=list)


def _reject_member(name: str, seen_normalized: dict[str, str], limits: IngestLimits) -> PurePosixPath:
    """Validate an archive member name, returning its relative path.

    Raises IngestError on anything hostile. Never rewrites the name.
    """
    if not name or name in (".", "/"):
        raise IngestError("empty_member_name", name)

    pure = PurePosixPath(name)

    if pure.is_absolute() or name.startswith("/") or name.startswith("\\"):
        raise IngestError("absolute_path", name)
    if any(part == ".." for part in pure.parts):
        raise IngestError("path_traversal", name)
    # Windows drive letters and UNC paths reach us as ordinary member names.
    if len(name) > 1 and name[1] == ":":
        raise IngestError("drive_letter_path", name)
    if len(pure.parts) > limits.max_depth:
        raise IngestError("path_too_deep", name)
    for part in pure.parts:
        if len(part.encode("utf-8", "surrogatepass")) > limits.max_name_bytes:
            raise IngestError("name_too_long", part[:64])
        if "\x00" in part:
            raise IngestError("null_byte_in_name", name)

    # Two members that differ in bytes but land on the same path after the
    # filesystem's Unicode handling would let a later entry overwrite an
    # earlier one. Refuse rather than pick a winner.
    normalized = unicodedata.normalize("NFC", str(pure)).casefold()
    if normalized in seen_normalized and seen_normalized[normalized] != str(pure):
        raise IngestError("unicode_path_collision", f"{seen_normalized[normalized]} vs {name}")
    seen_normalized[normalized] = str(pure)

    return pure


def _check_escape(dest_root: Path, target: Path) -> None:
    """Belt-and-braces: the resolved target must stay inside dest_root."""
    root = dest_root.resolve()
    try:
        resolved = target.resolve()
    except OSError as exc:  # pragma: no cover - resolution failure is itself hostile
        raise IngestError("unresolvable_path", str(target)) from exc
    if root != resolved and root not in resolved.parents:
        raise IngestError("escapes_destination", str(target))


def _is_archive(path: Path) -> bool:
    lowered = path.name.lower()
    return any(lowered.endswith(suffix) for suffix in ARCHIVE_SUFFIXES)


def _extract_zip(archive: Path, dest: Path, limits: IngestLimits, result: IngestResult) -> None:
    with zipfile.ZipFile(archive) as zf:
        infos = zf.infolist()
        if len(infos) > limits.max_files:
            raise IngestError("too_many_files", f"{len(infos)} > {limits.max_files}")

        seen: dict[str, str] = {}
        for info in infos:
            if info.is_dir():
                _reject_member(info.filename.rstrip("/"), seen, limits)
                continue

            rel = _reject_member(info.filename, seen, limits)

            # Zip stores unix mode in the top 16 bits of external_attr.
            mode = info.external_attr >> 16
            if mode and not _is_regular_mode(mode):
                raise IngestError("non_regular_member", info.filename)

            if info.file_size > limits.max_file_bytes:
                raise IngestError("member_too_large", f"{info.filename} ({info.file_size})")
            if info.compress_size > 0:
                ratio = info.file_size / info.compress_size
                if ratio > limits.max_ratio:
                    raise IngestError("compression_ratio", f"{info.filename} ({ratio:.0f}x)")

            result.total_bytes += info.file_size
            if result.total_bytes > limits.max_total_bytes:
                raise IngestError("total_size_exceeded", str(result.total_bytes))

            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            _check_escape(dest, target.parent)
            with zf.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out, length=1024 * 64)
            _record(target, rel, result)


def _is_regular_mode(mode: int) -> bool:
    import stat as _stat

    return _stat.S_ISREG(mode) or (mode & 0o170000) == 0


def _extract_tar(archive: Path, dest: Path, limits: IngestLimits, result: IngestResult) -> None:
    with tarfile.open(archive, "r:*") as tf:
        seen: dict[str, str] = {}
        count = 0
        for member in tf:
            if member.isdir():
                _reject_member(member.name.rstrip("/"), seen, limits)
                continue
            if member.issym() or member.islnk():
                # A symlink or hard link is how an archive reaches outside its
                # own tree. There is no benign need for one in an audit target.
                raise IngestError("link_member", f"{member.name} -> {member.linkname}")
            if member.ischr() or member.isblk() or member.isfifo() or member.isdev():
                raise IngestError("device_member", member.name)
            if not member.isfile():
                raise IngestError("non_regular_member", member.name)

            count += 1
            if count > limits.max_files:
                raise IngestError("too_many_files", f"> {limits.max_files}")

            rel = _reject_member(member.name, seen, limits)

            if member.size > limits.max_file_bytes:
                raise IngestError("member_too_large", f"{member.name} ({member.size})")
            result.total_bytes += member.size
            if result.total_bytes > limits.max_total_bytes:
                raise IngestError("total_size_exceeded", str(result.total_bytes))

            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            _check_escape(dest, target.parent)
            src = tf.extractfile(member)
            if src is None:
                raise IngestError("unreadable_member", member.name)
            with src, open(target, "wb") as out:
                shutil.copyfileobj(src, out, length=1024 * 64)
            _record(target, rel, result)

        # Whole-archive ratio check, once the uncompressed total is known.
        compressed = archive.stat().st_size
        if compressed > 0 and result.total_bytes / compressed > limits.max_ratio:
            raise IngestError(
                "compression_ratio",
                f"archive ({result.total_bytes / compressed:.0f}x)",
            )


def _record(target: Path, rel: PurePosixPath, result: IngestResult) -> None:
    target.chmod(0o600)
    result.file_count += 1
    if _is_archive(Path(rel.name)):
        # Staged as an ordinary file. Never recursively extracted.
        result.nested_archives.append(str(rel))


def stage_archive(
    archive_path: Path,
    dest_dir: Path,
    limits: IngestLimits | None = None,
) -> IngestResult:
    """Extract an untrusted archive into ``dest_dir``.

    Raises:
        IngestError: on any safety violation. Partial output is removed, since a
            half-extracted hostile archive is worse than none.
    """
    limits = limits or IngestLimits()
    dest_dir.mkdir(parents=True, exist_ok=True)
    result = IngestResult(root=dest_dir)

    try:
        if archive_path.name.lower().endswith(".zip"):
            _extract_zip(archive_path, dest_dir, limits, result)
        elif _is_archive(archive_path):
            _extract_tar(archive_path, dest_dir, limits, result)
        else:
            raise IngestError("unsupported_format", archive_path.name)
    except IngestError:
        shutil.rmtree(dest_dir, ignore_errors=True)
        raise
    except (zipfile.BadZipFile, tarfile.TarError) as exc:
        shutil.rmtree(dest_dir, ignore_errors=True)
        raise IngestError("corrupt_archive", str(exc)) from exc

    if result.file_count == 0:
        shutil.rmtree(dest_dir, ignore_errors=True)
        raise IngestError("empty_archive", archive_path.name)

    logger.info(
        "Staged %s: %d files, %d bytes, %d nested archives left unextracted",
        archive_path.name, result.file_count, result.total_bytes, len(result.nested_archives),
    )
    return result

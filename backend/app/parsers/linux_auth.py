"""Linux auth.log / secure parser.

Parses syslog-format auth logs and extracts:
  - SSH accepted/failed logins
  - sudo usage
  - PAM session open/close
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from backend.app.parsers.base import BaseParser, ParserResult
from backend.app.schemas.common import NormalizedEventType, SourceType

logger = logging.getLogger("aipam.parsers.linux_auth")

# Current year fallback (auth.log doesn't include year)
_CURRENT_YEAR = datetime.now(timezone.utc).year

# Regex patterns for common auth log lines
_RE_SSH_ACCEPTED = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+sshd\[\d+\]:\s+"
    r"Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)

_RE_SSH_FAILED = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+sshd\[\d+\]:\s+"
    r"Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)

_RE_SUDO = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+sudo:\s+(?P<user>\S+)\s+:.*COMMAND=(?P<command>.+)"
)

_RE_PAM_SESSION = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+.*pam_unix\(.*\):\s+session\s+(?P<action>opened|closed)\s+for\s+user\s+(?P<user>\S+)"
)

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


class LinuxAuthParser(BaseParser):
    """Parser for Linux auth.log / secure files."""

    @property
    def name(self) -> str:
        return "linux_auth"

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def supported_source_systems(self) -> list[str]:
        return ["linux_auth", "linux_secure"]

    def can_parse(self, path: Path, hint: str | None = None) -> bool:
        if hint and hint in self.supported_source_systems:
            return True
        name = path.name.lower()
        return "auth" in name and name.endswith(".log") or name == "secure"

    def parse(
        self,
        path: Path,
        job_id: str,
        source_type: SourceType = SourceType.log_bundle,
        exercise_id: str | None = None,
    ) -> Iterator[ParserResult]:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            logger.error("Failed to read %s: %s", path, exc)
            return

        for line_no, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
            result = self._try_parse_line(line, path, source_type, exercise_id, line_no)
            if result is not None:
                yield self._fill_provenance(result, path)

    def _try_parse_line(
        self, line: str, path: Path,
        source_type: SourceType, exercise_id: str | None, line_no: int,
    ) -> ParserResult | None:
        # Try SSH accepted
        m = _RE_SSH_ACCEPTED.search(line)
        if m:
            return self._build_result(
                m, "ssh_accepted", path, source_type, exercise_id, line_no, line,
            )
        # Try SSH failed
        m = _RE_SSH_FAILED.search(line)
        if m:
            return self._build_result(
                m, "ssh_failed", path, source_type, exercise_id, line_no, line,
            )
        # Try sudo
        m = _RE_SUDO.search(line)
        if m:
            return self._build_sudo(m, path, source_type, exercise_id, line_no, line)
        # Try PAM session
        m = _RE_PAM_SESSION.search(line)
        if m:
            return self._build_pam(m, path, source_type, exercise_id, line_no, line)

        return None

    def _build_result(
        self, m: re.Match, sub_type: str, path: Path,
        source_type: SourceType, exercise_id: str | None,
        line_no: int, raw_line: str,
    ) -> ParserResult:
        ts = _parse_syslog_ts(m.group("month"), m.group("day"), m.group("time"))
        hostname = m.group("hostname")
        user = m.group("user")
        ip = m.group("ip")
        port = int(m.group("port"))

        corr: dict[str, str] = {"hostname": hostname, "src_ip": ip, "username": user}
        return ParserResult(
            event_type=NormalizedEventType.auth,
            timestamp=ts,
            source_type=source_type,
            source_system="linux_auth",
            hostname=hostname,
            username=user,
            src_ip=ip,
            src_port=port,
            exercise_id=exercise_id,
            correlation_keys=corr,
            raw_ref=f"{path.name}:{line_no}",
            data={"sub_type": sub_type, "raw": raw_line},
        )

    def _build_sudo(
        self, m: re.Match, path: Path,
        source_type: SourceType, exercise_id: str | None,
        line_no: int, raw_line: str,
    ) -> ParserResult:
        ts = _parse_syslog_ts(m.group("month"), m.group("day"), m.group("time"))
        return ParserResult(
            event_type=NormalizedEventType.auth,
            timestamp=ts,
            source_type=source_type,
            source_system="linux_auth",
            hostname=m.group("hostname"),
            username=m.group("user"),
            exercise_id=exercise_id,
            correlation_keys={"hostname": m.group("hostname"), "username": m.group("user")},
            raw_ref=f"{path.name}:{line_no}",
            data={"sub_type": "sudo", "command": m.group("command").strip(), "raw": raw_line},
        )

    def _build_pam(
        self, m: re.Match, path: Path,
        source_type: SourceType, exercise_id: str | None,
        line_no: int, raw_line: str,
    ) -> ParserResult:
        ts = _parse_syslog_ts(m.group("month"), m.group("day"), m.group("time"))
        action = m.group("action")  # "opened" or "closed"
        return ParserResult(
            event_type=NormalizedEventType.auth,
            timestamp=ts,
            source_type=source_type,
            source_system="linux_auth",
            hostname=m.group("hostname"),
            username=m.group("user"),
            exercise_id=exercise_id,
            correlation_keys={"hostname": m.group("hostname"), "username": m.group("user")},
            raw_ref=f"{path.name}:{line_no}",
            data={"sub_type": f"pam_session_{action}", "raw": raw_line},
        )


def _parse_syslog_ts(month_str: str, day_str: str, time_str: str) -> datetime:
    """Parse syslog-style timestamp (no year) into a datetime."""
    month = _MONTHS.get(month_str, 1)
    day = int(day_str)
    h, m, s = (int(x) for x in time_str.split(":"))
    return datetime(_CURRENT_YEAR, month, day, h, m, s, tzinfo=timezone.utc)


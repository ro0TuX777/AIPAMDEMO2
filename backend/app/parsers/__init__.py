"""AIPAM telemetry parsers — plugin-style log normalization.

Parser families:
  - windows/   : Windows Event Logs, Sysmon
  - linux/     : auditd, auth.log, syslog, journald
  - network/   : firewall, proxy, DNS, DHCP, VPN, NetFlow/IPFIX
  - c2/        : Cobalt Strike, Mythic, Sliver, custom C2 frameworks
  - custom/    : VSAT modem, OT/ICS, appliance-specific logs
"""

from backend.app.parsers.base import BaseParser, ParserResult
from backend.app.parsers.registry import ParserRegistry, get_parser_registry

# Re-export V1 Zeek/Suricata parsers so existing imports keep working
from backend.app.legacy_parsers import parse_zeek_conn, parse_suricata_eve  # noqa: F401

__all__ = [
    "BaseParser",
    "ParserResult",
    "ParserRegistry",
    "get_parser_registry",
    "register_all_parsers",
    "parse_zeek_conn",
    "parse_suricata_eve",
]


def register_all_parsers() -> ParserRegistry:
    """Instantiate and register all built-in parsers into the default registry.

    Safe to call multiple times — already-registered parsers are overwritten.
    Returns the populated registry.
    """
    from backend.app.parsers.c2_callback import C2CallbackParser
    from backend.app.parsers.c2_tasking import C2TaskingParser
    from backend.app.parsers.dns import DnsParser
    from backend.app.parsers.firewall import FirewallParser
    from backend.app.parsers.linux_auth import LinuxAuthParser
    from backend.app.parsers.proxy import ProxyParser
    from backend.app.parsers.sysmon import SysmonParser
    from backend.app.parsers.windows_evtx import WindowsEvtxParser

    registry = get_parser_registry()
    for parser_cls in (
        WindowsEvtxParser,
        SysmonParser,
        LinuxAuthParser,
        FirewallParser,
        ProxyParser,
        DnsParser,
        C2CallbackParser,
        C2TaskingParser,
    ):
        registry.register(parser_cls())
    return registry


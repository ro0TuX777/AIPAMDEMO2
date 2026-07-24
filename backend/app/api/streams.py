"""
Stream forensics endpoints — SO-CRATES-style raw stream analysis.

GET /jobs/{jobId}/streams                 – list PCAP files available in the job
GET /jobs/{jobId}/streams/ascii           – ASCII transcript of a TCP/UDP stream (tshark)
GET /jobs/{jobId}/streams/hexdump         – per-packet hexdump of a stream (tcpdump -X)
GET /jobs/{jobId}/streams/pcap            – carve a single stream into a downloadable PCAP (tcpdump)

A stream is identified by the 4-tuple (src, sport, dst, dport) plus protocol.
"""

from __future__ import annotations

import ipaddress
import logging
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from backend.app.api.deps import get_db, get_request_id, verify_token
from backend.app.config_v2 import Settings, get_settings
from backend.app.models.job import Job
from backend.app.schemas.stream import (
    StreamHexdumpResponse,
    StreamHexPacket,
    StreamPcapItem,
    StreamPcapListResponse,
    StreamTranscriptResponse,
)

logger = logging.getLogger("aipam.streams")

router = APIRouter(tags=["Streams"], dependencies=[Depends(verify_token)])

MAX_TRANSCRIPT_CHARS = 100_000
MAX_HEXDUMP_PACKETS = 500
_SUBPROCESS_TIMEOUT = 120


def _require_job(db: Session, job_id: str) -> Job:
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


def _input_dir(settings: Settings, job_id: str) -> Path:
    return settings.aipam_job_root / job_id / "input"


def _list_pcaps(input_dir: Path) -> list[Path]:
    """Return real PCAP files (no symlinks/hidden) in the job input dir, sorted."""
    if not input_dir.exists():
        return []
    found: list[Path] = []
    for p in sorted(input_dir.iterdir()):
        if p.is_symlink() or p.name.startswith("."):
            continue
        if p.suffix.lower() in (".pcap", ".pcapng"):
            found.append(p)
    return found


def _resolve_pcap(input_dir: Path, pcap: str | None) -> Path:
    """Resolve which PCAP to operate on; guard against path traversal."""
    pcaps = _list_pcaps(input_dir)
    if not pcaps:
        raise HTTPException(status_code=404, detail="No PCAP found for this job")
    if pcap is None:
        return pcaps[0]
    if "/" in pcap or "\\" in pcap or pcap in ("..", "."):
        raise HTTPException(status_code=400, detail="Invalid pcap name")
    for p in pcaps:
        if p.name == pcap:
            return p
    raise HTTPException(status_code=404, detail=f"PCAP '{pcap}' not found in job")


def _validate_endpoint(src: str, sport: int, dst: str, dport: int, proto: str) -> str:
    """Validate the stream 4-tuple/proto and return the normalised protocol."""
    for ip in (src, dst):
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid IP address: {ip}")
    for port in (sport, dport):
        if not (0 <= port <= 65535):
            raise HTTPException(status_code=400, detail=f"Invalid port: {port}")
    p = proto.lower()
    if p not in ("tcp", "udp"):
        raise HTTPException(status_code=400, detail="proto must be 'tcp' or 'udp'")
    return p


def _bpf(src: str, sport: int, dst: str, dport: int, proto: str) -> str:
    """Bidirectional BPF filter matching a single stream by 4-tuple."""
    return (
        f"{proto} and host {src} and host {dst} "
        f"and port {sport} and port {dport}"
    )


def _require_tool(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise HTTPException(
            status_code=503,
            detail=f"Required tool '{name}' is not installed on the server",
        )
    return path


@router.get("/jobs/{job_id}/streams", response_model=StreamPcapListResponse)
async def list_streams(
    job_id: str,
    response: Response,
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """List the PCAP files available for stream extraction within a job."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id
    pcaps = _list_pcaps(_input_dir(settings, job_id))
    return StreamPcapListResponse(
        items=[
            StreamPcapItem(name=p.name, size_bytes=p.stat().st_size, label=p.stem)
            for p in pcaps
        ]
    )


@router.get("/jobs/{job_id}/streams/ascii", response_model=StreamTranscriptResponse)
async def stream_ascii(
    job_id: str,
    response: Response,
    src: str = Query(...),
    sport: int = Query(...),
    dst: str = Query(...),
    dport: int = Query(...),
    proto: str = Query("tcp"),
    pcap: str | None = Query(None),
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Extract a decoded ASCII transcript for a single stream using tshark."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id
    norm_proto = _validate_endpoint(src, sport, dst, dport, proto)
    pcap_path = _resolve_pcap(_input_dir(settings, job_id), pcap)
    tshark = _require_tool("tshark")

    follow = f"follow,{norm_proto},ascii,{src}:{sport},{dst}:{dport}"
    cmd = [tshark, "-r", str(pcap_path), "-q", "-z", follow]
    try:
        result = subprocess.run(
            cmd, capture_output=True, timeout=_SUBPROCESS_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="tshark timed out")

    text = result.stdout.decode("utf-8", errors="replace")
    truncated = len(text) > MAX_TRANSCRIPT_CHARS
    if truncated:
        text = text[:MAX_TRANSCRIPT_CHARS]
    return StreamTranscriptResponse(
        protocol=norm_proto,
        transcript=text,
        truncated=truncated,
        byte_count=len(text),
    )


def _parse_hexdump(raw: str) -> tuple[list[StreamHexPacket], bool]:
    """Group `tcpdump -X` output into per-packet header + hex lines."""
    packets: list[StreamHexPacket] = []
    current: StreamHexPacket | None = None
    truncated = False
    for line in raw.splitlines():
        if not line:
            continue
        # Hex/ascii rows are indented; packet header lines start at column 0.
        if line[0].isspace():
            if current is not None:
                current.lines.append(line.strip())
        else:
            if len(packets) >= MAX_HEXDUMP_PACKETS:
                truncated = True
                break
            current = StreamHexPacket(header=line.strip(), lines=[])
            packets.append(current)
    return packets, truncated


@router.get("/jobs/{job_id}/streams/hexdump", response_model=StreamHexdumpResponse)
async def stream_hexdump(
    job_id: str,
    response: Response,
    src: str = Query(...),
    sport: int = Query(...),
    dst: str = Query(...),
    dport: int = Query(...),
    proto: str = Query("tcp"),
    pcap: str | None = Query(None),
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Extract a per-packet hexdump for a single stream using tcpdump -X."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id
    norm_proto = _validate_endpoint(src, sport, dst, dport, proto)
    pcap_path = _resolve_pcap(_input_dir(settings, job_id), pcap)
    tcpdump = _require_tool("tcpdump")

    cmd = [tcpdump, "-nn", "-X", "-r", str(pcap_path),
           _bpf(src, sport, dst, dport, norm_proto)]
    try:
        result = subprocess.run(
            cmd, capture_output=True, timeout=_SUBPROCESS_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="tcpdump timed out")

    packets, truncated = _parse_hexdump(result.stdout.decode("utf-8", errors="replace"))
    return StreamHexdumpResponse(
        protocol=norm_proto, packets=packets, truncated=truncated,
    )


@router.get("/jobs/{job_id}/streams/pcap")
async def stream_pcap(
    job_id: str,
    response: Response,
    src: str = Query(...),
    sport: int = Query(...),
    dst: str = Query(...),
    dport: int = Query(...),
    proto: str = Query("tcp"),
    pcap: str | None = Query(None),
    request_id: str = Depends(get_request_id),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Carve a single stream into a standalone PCAP for download (tcpdump -w)."""
    _require_job(db, job_id)
    response.headers["X-Request-Id"] = request_id
    norm_proto = _validate_endpoint(src, sport, dst, dport, proto)
    pcap_path = _resolve_pcap(_input_dir(settings, job_id), pcap)
    tcpdump = _require_tool("tcpdump")

    out_dir = Path(tempfile.mkdtemp(prefix="aipam-carve-"))
    out_path = out_dir / f"stream-{src}_{sport}-{dst}_{dport}-{uuid.uuid4().hex[:8]}.pcap"
    cmd = [tcpdump, "-r", str(pcap_path), "-w", str(out_path),
           _bpf(src, sport, dst, dport, norm_proto)]
    try:
        subprocess.run(cmd, capture_output=True, timeout=_SUBPROCESS_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="tcpdump timed out")

    if not out_path.exists() or out_path.stat().st_size == 0:
        raise HTTPException(status_code=404, detail="No packets matched the requested stream")

    return FileResponse(
        path=str(out_path),
        filename=out_path.name,
        media_type="application/vnd.tcpdump.pcap",
    )

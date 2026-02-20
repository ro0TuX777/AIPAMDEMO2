#!/usr/bin/env python3
"""Parse Malware-Traffic-Analysis (MTA) training exercise assets into Q&A JSONL.

Goal:
  Convert exercise QUESTIONS (page.html) + ANSWERS (usually answer-key PDFs/HTML)
  into ChatML-style training examples:

    {"messages": [{"role":"system",...},{"role":"user",...},{"role":"assistant",...}]}

This script is intentionally dependency-light:
  - Uses BeautifulSoup (bs4) if available (it is in this repo environment)
  - Uses `pdftotext` for PDF -> text (preferred; no Python PDF deps)
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from contextlib import nullcontext
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


REPO_ROOT = Path(__file__).resolve().parents[1]


def to_repo_rel(p: Path) -> str:
    try:
        return str(p.relative_to(REPO_ROOT))
    except Exception:
        return str(p)


SYSTEM_PROMPT_QA = (
    "You are a senior network security analyst. "
    "Answer the question precisely. "
    "If the answer is an IOC (IP/domain/URL/hash), preserve it exactly. "
    "Keep the explanation brief and factual."
)


IOC_IP_RE = re.compile(r"\b(?:(?:[0-9]{1,3})\.){3}(?:[0-9]{1,3})\b")
IOC_URL_RE = re.compile(r"\bhttps?://[^\s\]\)\}\"\']+")
IOC_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
IOC_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
IOC_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")


def _safe_read_text(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="ignore")


def extract_text_from_pdf(pdf_path: Path, timeout_sec: int = 60) -> str:
    """Extract text from PDF via `pdftotext` (stdout)."""
    if not shutil_which("pdftotext"):
        raise RuntimeError("pdftotext not found on PATH; cannot parse PDFs")
    proc = subprocess.run(
        ["pdftotext", "-layout", str(pdf_path), "-"],
        capture_output=True,
        text=True,
        timeout=timeout_sec,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"pdftotext failed (rc={proc.returncode}) for {pdf_path}: {proc.stderr[:2000]}"
        )
    return proc.stdout


def shutil_which(cmd: str) -> Optional[str]:
    # Avoid importing stdlib shutil if a local module shadows it.
    try:
        import shutil as _shutil  # type: ignore

        return _shutil.which(cmd)
    except Exception:
        return None


def extract_text_from_html(html_path: Path) -> str:
    html = _safe_read_text(html_path)
    try:
        from bs4 import BeautifulSoup  # type: ignore

        soup = BeautifulSoup(html, "html.parser")
        # Remove nav/footer noise a bit.
        for tag in soup(["script", "style"]):
            tag.decompose()
        return soup.get_text("\n")
    except Exception:
        # Fallback: strip tags crudely.
        return re.sub(r"<[^>]+>", "\n", html)


def extract_text_generic(p: Path) -> str:
    ext = p.suffix.lower()
    if ext == ".pdf":
        return extract_text_from_pdf(p)
    if ext in {".html", ".htm"}:
        return extract_text_from_html(p)
    return _safe_read_text(p)


@dataclass
class Question:
    level: Optional[int]
    number: int
    text: str


def parse_questions_from_text(text: str) -> List[Question]:
    """Parse MTA-style questions from a text blob (HTML/PDF/TXT).

    Supports patterns seen across exercises:
      - LEVEL 1 QUESTIONS:
      - QUESTIONS:
      - 1) ... / 1. ... / Q1: ...

    Stops collecting questions when an answers section begins.
    """
    text = text.replace("\r", "")
    lines = [ln.rstrip() for ln in text.splitlines()]

    def _parse_isc_end_of_year_quiz_family_questions() -> List[Question]:
        """Handle ISC 'End of Year Traffic Analysis Quiz' answer PDFs.

        These PDFs contain a SCENARIO section like:
          You have six pcaps... Identify the malware family...
          • 2020-12-31-traffic-analysis-quiz-01.pcap
          ...
        and often do not contain a QUESTIONS header.
        """

        head = "\n".join([ln.strip() for ln in lines[:60] if (ln or "").strip()])
        head_u = head.upper()
        if "TRAFFIC ANALYSIS QUIZ" not in head_u:
            return []
        if "SCENARIO" not in head_u:
            return []
        if "MALWARE FAMILY" not in head_u:
            return []

        pcap_re = re.compile(
            r"\b([0-9]{4}-[0-9]{2}-[0-9]{2}-traffic-analysis-quiz-[0-9]{2}\.pcap)\b",
            re.IGNORECASE,
        )

        try:
            scen_idx = next(i for i, ln in enumerate(lines) if (ln or "").strip().upper().startswith("SCENARIO"))
        except StopIteration:
            return []

        # Try to stop at an ANSWERS header if present.
        stop_idx = min(len(lines), scen_idx + 80)
        for i in range(scen_idx, min(len(lines), scen_idx + 200)):
            if (lines[i] or "").strip().upper().startswith("ANSWERS"):
                stop_idx = i
                break

        pcaps: List[str] = []
        seen = set()
        for ln in lines[scen_idx:stop_idx]:
            for m in pcap_re.finditer(ln or ""):
                p = m.group(1).strip()
                if p and p not in seen:
                    seen.add(p)
                    pcaps.append(p)

        # Guard: require multiple pcaps to avoid false positives.
        if len(pcaps) < 3:
            return []

        qs: List[Question] = []
        for i, pcap in enumerate(pcaps, 1):
            qs.append(
                Question(
                    level=None,
                    number=i,
                    text=f"For {pcap}, identify the malware family that caused the infection.",
                )
            )
        return qs

    isc_qs = _parse_isc_end_of_year_quiz_family_questions()
    if isc_qs:
        return isc_qs

    level_q_only_re = re.compile(r"^\s*LEVEL\s+([0-9]+)\s+QUESTIONS:?\s*$", re.IGNORECASE)
    level_q_inline_re = re.compile(r"^\s*LEVEL\s+([0-9]+)\s+QUESTIONS?:\s*(.+)\s*$", re.IGNORECASE)
    generic_q_hdr_re = re.compile(r"^\s*QUESTIONS:?\s*$", re.IGNORECASE)

    # Many older MTA exercises use BASIC / MORE ADVANCED / EXTRA (instead of LEVEL 1/2/3).
    basic_q_hdr_re = re.compile(r"^\s*BASIC\s+QUESTIONS:?\s*$", re.IGNORECASE)
    adv_q_hdr_re = re.compile(r"^\s*(?:MORE\s+ADVANCED|ADVANCED)\s+QUESTIONS:?\s*$", re.IGNORECASE)
    extra_q_hdr_re = re.compile(r"^\s*EXTRA\s+QUESTIONS:?\s*$", re.IGNORECASE)

    # Detect answer sections so we can stop collecting questions when an answers block begins.
    level_ans_hdr_re = re.compile(r"^\s*LEVEL\s+([0-9]+)\s+ANSWERS:?\s*$", re.IGNORECASE)
    generic_ans_hdr_re = re.compile(r"^\s*ANSWERS:?\s*$", re.IGNORECASE)
    basic_ans_hdr_re = re.compile(r"^\s*BASIC\s+ANSWERS:?\s*$", re.IGNORECASE)
    adv_ans_hdr_re = re.compile(r"^\s*(?:MORE\s+ADVANCED|ADVANCED)\s+ANSWERS:?\s*$", re.IGNORECASE)
    extra_ans_hdr_re = re.compile(r"^\s*EXTRA\s+ANSWERS:?\s*$", re.IGNORECASE)
    ans_to_adv_hdr_re = re.compile(
        r"^\s*ANSWERS\s+TO\s+THE\s+(?:MORE\s+ADVANCED|ADVANCED)\s+QUESTIONS:?\s*$", re.IGNORECASE
    )
    ans_to_extra_hdr_re = re.compile(r"^\s*ANSWERS\s+TO\s+THE\s+EXTRA\s+QUESTIONS:?\s*$", re.IGNORECASE)
    ans_line_re = re.compile(r"^\s*Answer\s*[:\-\u2013]", re.IGNORECASE)

    # Allow minor spacing variations like "1 )" or "1 ." as seen in some PDF-to-text outputs.
    q_num_parens_re = re.compile(r"^\s*([0-9]+)\s*\)\s*(.+)\s*$")
    q_num_dot_re = re.compile(r"^\s*([0-9]+)\s*\.\s*(.+)\s*$")
    q_qprefix_re = re.compile(r"^\s*Q\s*([0-9]+)\s*[:\.-]\s*(.+)\s*$", re.IGNORECASE)
    bullet_q_re = re.compile(r"^\s*[\u2022\-\*]\s*(.+?)\s*$")

    def parse_q_start(ln: str) -> Optional[Tuple[int, str]]:
        for r in (q_num_parens_re, q_num_dot_re, q_qprefix_re):
            m = r.match(ln)
            if m:
                try:
                    return (int(m.group(1)), (m.group(2) or "").strip())
                except Exception:
                    return None
        return None

    # If the doc references questions early, allow numbered questions even without a header.
    mentions_questions = any("QUESTION" in (ln or "").upper() for ln in lines[:80])

    out: Dict[Tuple[Optional[int], int], Question] = {}
    current_level: Optional[int] = None
    in_questions = False
    cur_num: Optional[int] = None
    cur_lines: List[str] = []
    next_auto_num = 1

    def flush_current() -> None:
        nonlocal cur_num, cur_lines
        if cur_num is None:
            return
        qtext = " ".join([s.strip() for s in cur_lines if s.strip()]).strip()
        if qtext:
            out.setdefault((current_level, cur_num), Question(level=current_level, number=cur_num, text=qtext))
        cur_num = None
        cur_lines = []

    def is_answers_header(s: str) -> bool:
        return bool(
            level_ans_hdr_re.match(s)
            or generic_ans_hdr_re.match(s)
            or basic_ans_hdr_re.match(s)
            or adv_ans_hdr_re.match(s)
            or extra_ans_hdr_re.match(s)
            or ans_to_adv_hdr_re.match(s)
            or ans_to_extra_hdr_re.match(s)
            or ans_line_re.match(s)
        )

    for ln in lines:
        s = (ln or "").strip()
        if not s:
            continue

        # Stop once answers begin.
        if is_answers_header(s):
            flush_current()
            in_questions = False
            continue

        # Start questions sections.
        m = level_q_only_re.match(s)
        if m:
            flush_current()
            in_questions = True
            next_auto_num = 1
            try:
                current_level = int(m.group(1))
            except Exception:
                current_level = None
            continue

        m = level_q_inline_re.match(s)
        if m:
            flush_current()
            in_questions = True
            next_auto_num = 1
            try:
                current_level = int(m.group(1))
            except Exception:
                current_level = None
            remainder = (m.group(2) or "").strip()
            if remainder:
                q = parse_q_start(remainder)
                if q:
                    cur_num, first = q
                    cur_lines = [first]
                    next_auto_num = max(next_auto_num, cur_num + 1)
            continue

        if generic_q_hdr_re.match(s):
            flush_current()
            in_questions = True
            current_level = None
            next_auto_num = 1
            continue

        # BASIC / ADVANCED / EXTRA sections (map to pseudo-levels 1/2/3)
        if basic_q_hdr_re.match(s):
            flush_current()
            in_questions = True
            current_level = 1
            next_auto_num = 1
            continue
        if adv_q_hdr_re.match(s):
            flush_current()
            in_questions = True
            current_level = 2
            next_auto_num = 1
            continue
        if extra_q_hdr_re.match(s):
            flush_current()
            in_questions = True
            current_level = 3
            next_auto_num = 1
            continue

        if not in_questions and not mentions_questions:
            continue

        q = parse_q_start(s)
        if q:
            flush_current()
            cur_num, first = q
            cur_lines = [first]
            in_questions = True
            next_auto_num = max(next_auto_num, cur_num + 1)
            continue

        # Bullet questions (common in some quiz PDFs): auto-number them in the order encountered.
        bm = bullet_q_re.match(s)
        if bm and in_questions:
            flush_current()
            cur_num = next_auto_num
            next_auto_num += 1
            cur_lines = [(bm.group(1) or "").strip()]
            continue

        if in_questions and cur_num is not None:
            cur_lines.append(s)

    flush_current()

    # Some answer keys do not include a QUESTIONS section. Instead they list prompt lines
    # ending in ':' (or '?') under an ANSWERS header, similar to the HTML linked answer pages.
    # When our normal question parsing finds nothing, attempt to synthesize questions from
    # these prompt lines so we can pair them with the auto-numbered answers.
    if not out:
        def _parse_label_colon_questions_from_answers() -> List[Question]:
            # Locate an answers header.
            ans_idx: Optional[int] = None
            for i, ln in enumerate(lines):
                s = (ln or "").strip()
                if not s:
                    continue
                if is_answers_header(s):
                    ans_idx = i
                    break
            if ans_idx is None:
                return []

            def is_prompt_line(s: str) -> bool:
                s2 = (s or "").strip()
                if not s2:
                    return False
                if s2.upper().startswith("HINT"):
                    return False
                if not (s2.endswith(":") or s2.endswith("?")):
                    return False
                core = s2[:-1].strip() if s2.endswith(":") else s2.strip()
                if len(core) < 8 or len(core) > 220:
                    return False
                if not re.search(r"[A-Za-z]", core):
                    return False
                # Avoid treating pure IOCs or obvious section headers as prompts.
                if (
                    IOC_IP_RE.fullmatch(core)
                    or IOC_MD5_RE.fullmatch(core)
                    or IOC_SHA1_RE.fullmatch(core)
                    or IOC_SHA256_RE.fullmatch(core)
                ):
                    return False
                if core.upper() in {"NOTICE", "TRAFFIC", "ANSWERS", "HINTS"}:
                    return False
                return True

            # Quick guard: require at least 2 prompt-like lines soon after the ANSWERS header.
            prompts: List[str] = []
            for ln in lines[ans_idx + 1 : ans_idx + 500]:
                s = (ln or "").strip()
                if not s:
                    continue
                if s.upper().startswith("HINT"):
                    break
                if is_prompt_line(s):
                    prompts.append(s)

            if len(prompts) < 2:
                return []

            qs: List[Question] = []
            for i, p in enumerate(prompts, 1):
                t = (p or "").strip()
                if t.endswith(":"):
                    t = t[:-1].strip()
                # Make it question-like, but keep original phrasing.
                if not t.endswith("?"):
                    t = t + "?"
                qs.append(Question(level=None, number=i, text=t))
            return qs

        lc_qs = _parse_label_colon_questions_from_answers()
        if lc_qs:
            return lc_qs

    return [out[k] for k in sorted(out.keys(), key=lambda t: ((t[0] is None), t[0] or 0, t[1]))]


def parse_questions_from_page(page_html: Path) -> List[Question]:
    """Parse questions from the exercise page.html.

    Typical pattern:
      <h2>QUESTIONS</h2>
      LEVEL 1 QUESTIONS: <blockquote>1) ...</blockquote>
    """
    def _extract_your_task_list_items() -> List[str]:
        """Extract bullet/task list items under a 'YOUR TASK' section.

        Many MTA exercise pages do not have a QUESTIONS section. Instead they have:
          <h2>YOUR TASK</h2>
          <p>... Your report should include:</p>
          <ul><li>...</li></ul>
        """
        html = _safe_read_text(page_html)
        try:
            from bs4 import BeautifulSoup  # type: ignore

            soup = BeautifulSoup(html, "html.parser")
            for tag in soup(["script", "style"]):
                tag.decompose()

            hdr = None
            for t in soup.find_all(["h1", "h2", "h3", "h4"]):
                txt = (t.get_text(" ", strip=True) or "").strip()
                if txt.upper() == "YOUR TASK" or "YOUR TASK" in txt.upper():
                    hdr = t
                    break

            # Fallback: locate the paragraph that contains "report/write-up should include/contain".
            if hdr is None:
                needle = soup.find(string=re.compile(r"(report|write-up)\s+should\s+(include|contain)", re.IGNORECASE))
                if needle is not None:
                    hdr = getattr(needle, "parent", None)

            # Fallback: look for <h2>TASK</h2> header.
            if hdr is None:
                for t in soup.find_all(["h1", "h2", "h3", "h4"]):
                    txt = (t.get_text(" ", strip=True) or "").strip().upper()
                    if txt == "TASK":
                        hdr = t
                        break

            if hdr is None:
                return []

            ul = hdr.find_next("ul")
            if ul is None:
                return []

            items: List[str] = []
            # Prefer direct children first, then fall back to any nested lis.
            lis = ul.find_all("li", recursive=False) or ul.find_all("li")
            for li in lis:
                s = (li.get_text(" ", strip=True) or "").strip()
                if s:
                    items.append(s)
            return items
        except Exception:
            return []

    raw = extract_text_from_html(page_html)
    raw = raw.replace("\r", "")

    # 1) Typical pattern: a QUESTIONS header.
    idx = raw.upper().find("QUESTIONS")
    if idx != -1:
        qs = parse_questions_from_text(raw[idx:])
        if qs:
            return qs

    # 2) Common pattern: YOUR TASK + bullet list.
    items = _extract_your_task_list_items()
    if items:
        synthetic = "QUESTIONS:\n" + "\n".join([f"- {it}" for it in items])
        qs = parse_questions_from_text(synthetic)
        if qs:
            return qs

    # 3) Best-effort fallback: slice after 'YOUR TASK' in extracted text.
    tidx = raw.upper().find("YOUR TASK")
    if tidx != -1:
        sub = raw[tidx:]
        aidx = sub.upper().find("ANSWERS")
        if aidx != -1:
            sub = sub[:aidx]
        # Treat short, non-empty lines as task bullets.
        lines = [ln.strip() for ln in sub.splitlines() if ln.strip()]
        task_lines: List[str] = []
        for ln in lines:
            up = ln.upper()
            if up in {"YOUR TASK", "TASK", "REPORT SHOULD INCLUDE"}:
                continue
            if len(ln) > 160:
                continue
            if not re.search(r"[A-Za-z]", ln):
                continue
            task_lines.append(ln)
        if task_lines:
            synthetic = "QUESTIONS:\n" + "\n".join([f"- {it}" for it in task_lines])
            qs = parse_questions_from_text(synthetic)
            if qs:
                return qs

    # 4) Final fallback: run the generic text parser on the whole page.
    return parse_questions_from_text(raw)


@dataclass
class Answer:
    level: Optional[int]
    number: int
    answer: str
    explanation: str


def parse_answers_from_text(text: str) -> Dict[Tuple[Optional[int], int], Answer]:
    """Parse answers from answer-key text.

    Handles common MTA PDF pattern:
      LEVEL 1 ANSWERS:
      1) ...
      Answer: ...
      Explanation: ...
    """
    # Normalize special characters from PDFs (soft hyphen, non-breaking space).
    text = text.replace("\u00AD", "")  # Soft hyphen (often in PDF text)
    text = text.replace("\u00A0", " ")  # Non-breaking space -> normal space
    text = text.replace("\r", "")
    # Collapse multiple spaces to single space (common in PDFs with layout issues).
    text = re.sub(r"  +", " ", text)
    lines = [ln.rstrip() for ln in text.splitlines()]

    level_ans_re = re.compile(r"^\s*LEVEL\s+([0-9]+)\s+ANSWERS:?\s*$", re.IGNORECASE)
    generic_ans_re = re.compile(r"^\s*ANSWERS:?\s*$", re.IGNORECASE)

    # Some answer PDFs embed answers immediately after a per-PCAP filename label, without an "ANSWERS" header.
    # Example: "2015-01-18-traffic-analysis-exercise-1-of-2.pcap" then numbered Q/A pairs.
    pcap_label_re = re.compile(r"^\s*[A-Za-z0-9][A-Za-z0-9._\-]*\.pcap(?:ng)?\s*$", re.IGNORECASE)

    # Many older MTA answer keys use BASIC / MORE ADVANCED / EXTRA headers
    # and then provide inline answers (answer content follows the numbered question,
    # without explicit Answer:/Explanation: markers).
    basic_ans_re = re.compile(r"^\s*BASIC\s+ANSWERS:?\s*$", re.IGNORECASE)
    adv_ans_re = re.compile(r"^\s*(?:MORE\s+ADVANCED|ADVANCED)\s+ANSWERS:?\s*$", re.IGNORECASE)
    extra_ans_re = re.compile(r"^\s*EXTRA\s+ANSWERS:?\s*$", re.IGNORECASE)
    ans_to_adv_re = re.compile(
        r"^\s*ANSWERS\s+TO\s+THE\s+(?:MORE\s+ADVANCED|ADVANCED)\s+QUESTIONS:?\s*$", re.IGNORECASE
    )
    ans_to_extra_re = re.compile(r"^\s*ANSWERS\s+TO\s+THE\s+EXTRA\s+QUESTIONS:?\s*$", re.IGNORECASE)

    level_q_re = re.compile(r"^\s*LEVEL\s+([0-9]+)\s+QUESTIONS:?\s*$", re.IGNORECASE)
    generic_q_re = re.compile(r"^\s*QUESTIONS:?\s*$", re.IGNORECASE)
    basic_q_re = re.compile(r"^\s*BASIC\s+QUESTIONS:?\s*$", re.IGNORECASE)
    adv_q_re = re.compile(r"^\s*(?:MORE\s+ADVANCED|ADVANCED)\s+QUESTIONS:?\s*$", re.IGNORECASE)
    extra_q_re = re.compile(r"^\s*EXTRA\s+QUESTIONS:?\s*$", re.IGNORECASE)

    # NOTE: Require '.' NOT to be followed by a digit to avoid false positives on IPs like "188.165.164.184".
    q_re = re.compile(r"^\s*([0-9]+)\s*(?:\)\s*(.*)|\.(?![0-9])\s*(.*))$")
    ans_re = re.compile(r"^\s*Answer\s*[:\-\u2013]\s*(.*)$", re.IGNORECASE)
    expl_re = re.compile(r"^\s*Explanation\s*[:\-\u2013]\s*(.*)$", re.IGNORECASE)

    current_level: Optional[int] = None
    in_answers = False
    current_qnum: Optional[int] = None
    current_answer_lines: List[str] = []
    current_expl_lines: List[str] = []
    current_inline: str = ""
    mode: Optional[str] = None  # "answer" | "explanation" | None

    # Whether the current answer section should default to collecting inline answers.
    # (Older "BASIC ANSWERS" PDFs: answer text starts on the next line after the question.)
    section_inline_default = False
    inline_collect = False

    out: Dict[Tuple[Optional[int], int], Answer] = {}

    # Common boilerplate/noise lines that sometimes get pulled into Answer/Explanation by pdftotext.
    noise_answers_hdr_re = re.compile(r"\bTRAFFIC\s+ANALYSIS\b.*\bANSWERS\b", re.IGNORECASE)

    def _is_noise_line(s: str) -> bool:
        s2 = (s or "").strip()
        if not s2:
            return False
        if noise_answers_hdr_re.search(s2):
            return True
        if re.match(r"^[-_]{3,}$", s2):
            return True
        if re.match(r"^PAGE\s+[0-9]+$", s2, flags=re.IGNORECASE):
            return True
        if re.match(r"^PAGE\s+[0-9]+\s+OF\s+[0-9]+$", s2, flags=re.IGNORECASE):
            return True
        return False

    def _looks_like_inline_answer_value(s: str) -> bool:
        s2 = (s or "").strip()
        if not s2:
            return False
        # If it still looks like a question, it's probably not an answer value.
        if "?" in s2:
            return False
        # Common high-signal answer shapes.
        if re.search(r"\b(?:(?:[0-9]{1,3})\.){3}(?:[0-9]{1,3})\b", s2):
            return True
        if re.search(r"\bhttps?://[^\s\]\)\}\"\']+", s2, flags=re.IGNORECASE):
            return True
        if re.search(r"\b[a-fA-F0-9]{32}\b", s2) or re.search(r"\b[a-fA-F0-9]{40}\b", s2) or re.search(
            r"\b[a-fA-F0-9]{64}\b", s2
        ):
            return True
        if re.search(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b", s2):
            return True
        # Short-ish strings are often single-line answers in these PDFs.
        return len(s2) <= 80


    def _parse_incident_report_style_answers() -> Dict[Tuple[Optional[int], int], Answer]:
	        """Parse common 'TRAFFIC ANALYSIS EXERCISE - ANSWERS' incident-report formats.

	        Many MTA answer keys (PDF/TXT) are written as a short incident report with sections
	        like SUMMARY / DETAILS / RECOMMENDATIONS, rather than numbered Q&A.

	        We emit answers that align to the common 'report should include' bullet questions.
	        Supported templates:
	          - 4-item report: date/time, host info, summary, recommendations
	          - 6-item email-driven infection report: host, MAC, OS, malicious email, malware, related traffic
	        """
	        # High-signal guard: only trigger on docs that clearly look like MTA answer reports.
	        head = "\n".join([ln.strip() for ln in lines[:40] if (ln or "").strip()])
	        head_u = head.upper()
	        if "TRAFFIC ANALYSIS" not in head_u or "ANSWER" not in head_u:
	            return {}

	        low = text.lower()
	        # Allow "details:" or "details of" (some PDFs use "Details of the infected host:").
	        has_summary = ("summary:" in low or "description of what happened" in low
	                       or "writeup:" in low)
	        has_details = "details:" in low or "details of" in low or "details" in low[:1500].lower()
	        if not has_summary or not has_details:
	            return {}

	        def _norm_space(s: str) -> str:
	            return re.sub(r"\s+", " ", (s or "").strip())

	        def _match_section_header(s: str) -> Optional[str]:
	            s2 = (s or "").strip()
	            if not s2:
	                return None
	            up = s2.upper()
	            # Most section headers end with ':' in these docs.
	            core = up[:-1].strip() if up.endswith(":") else up

	            # Canonicalize common sections.
	            if core == "SUMMARY" or core == "EXECUTIVE SUMMARY" or core == "WRITEUP":
	                return "summary"
	            # Some older exercises use "A description of what happened" instead of summary.
	            if core.startswith("A DESCRIPTION OF") or core == "DESCRIPTION OF WHAT HAPPENED":
	                return "summary"
	            if core == "DETAILS" or core == "VICTIM DETAILS" or core.startswith("DETAILS OF"):
	                return "details"
	            if core == "RECOMMENDATIONS":
	                return "recommendations"
	            if core == "TIMELINE":
	                return "timeline"
	            if core == "INFECTION TRAFFIC":
	                return "infection_traffic"
	            if core == "ALERTS":
	                return "alerts"
	            if core == "ASSOCIATED MALWARE":
	                return "associated_malware"
	            if core.startswith("INDICATORS OF COMPROMISE"):
	                return "iocs"
	            if core == "NOTES":
	                return "notes"
	            if core == "HINTS":
	                return "hints"
	            # The malicious-email block is sometimes a labeled mini-section.
	            if core.startswith("MALICIOUS EMAIL"):
	                return "malicious_email"
	            return None

	        # Split into sections.
	        sections: Dict[str, List[str]] = {}
	        cur: Optional[str] = None
	        for ln in lines:
	            s = (ln or "").rstrip()
	            key = _match_section_header(s)
	            if key is not None:
	                cur = key
	                sections.setdefault(cur, [])
	                continue
	            if cur is None:
	                continue
	            # Stop collecting at HINTS (usually screenshots / non-text).
	            if cur == "hints":
	                continue
	            if _is_noise_line(s):
	                continue
	            sections[cur].append(s)

	        def _section_text(name: str, *, max_chars: int = 4000) -> str:
	            raw_lines = [ln.strip() for ln in (sections.get(name) or []) if (ln or "").strip()]
	            t = "\n".join(raw_lines).strip()
	            if max_chars and len(t) > max_chars:
	                t = t[:max_chars].rstrip() + "..."
	            return t

	        # Parse key/value lines from DETAILS.
	        kv_re = re.compile(r"^\s*(?:[\u2022\-\*]\s*)?([^:]{3,80}?)\s*:\s*(.+?)\s*$")
	        kv: Dict[str, str] = {}
	        for ln in (sections.get("details") or []):
	            m = kv_re.match(ln or "")
	            if not m:
	                continue
	            k = _norm_space(m.group(1) or "")
	            v = _norm_space(m.group(2) or "")
	            if not k or not v:
	                continue
	            # Keep first occurrence.
	            kv.setdefault(k.lower(), v)

	        def _kv_get(*keys: str) -> str:
	            for k in keys:
	                v = kv.get(k.lower())
	                if v:
	                    return v
	            return ""

	        host = _kv_get("Infected computer's host name", "Computer Name", "Host name", "Hostname")
	        ip = _kv_get("Infected computer's IP address", "IP Address", "IP address")
	        mac = _kv_get("Infected computer's MAC address", "MAC Address", "MAC address")
	        os_ = _kv_get("Infected computer's operating system", "Operating system", "OS")
	        dt = _kv_get("Date/Time", "Date/time", "Date and time")

	        summary = _section_text("summary", max_chars=2400)
	        recs = _section_text("recommendations", max_chars=2400)

	        mal_email_block = _section_text("malicious_email", max_chars=2400)
	        assoc_malware = _section_text("associated_malware", max_chars=2400)
	        inf_traffic = _section_text("infection_traffic", max_chars=2400)
	        iocs = _section_text("iocs", max_chars=2400)

	        has_malicious_email = bool(mal_email_block or ("malicious email" in low))

	        out2: Dict[Tuple[Optional[int], int], Answer] = {}

	        # Template A: email-driven infection report (common older exercises).
	        if has_malicious_email:
	            if host:
	                out2[(None, 1)] = Answer(level=None, number=1, answer=host, explanation="")
	            if mac:
	                out2[(None, 2)] = Answer(level=None, number=2, answer=mac, explanation="")
	            if os_:
	                out2[(None, 3)] = Answer(level=None, number=3, answer=os_, explanation="")
	            if mal_email_block:
	                out2[(None, 4)] = Answer(level=None, number=4, answer=mal_email_block, explanation="")
	            if assoc_malware:
	                out2[(None, 5)] = Answer(level=None, number=5, answer=assoc_malware, explanation="")
	            traffic_block = inf_traffic or iocs
	            if traffic_block:
	                out2[(None, 6)] = Answer(level=None, number=6, answer=traffic_block, explanation="")

	            # Guard: require at least 3 answers to avoid accidental triggers.
	            if len(out2) >= 3:
	                return out2
	            return {}

	        # Template B: short report with date/time + host info + summary + recommendations/IOCs.
	        host_info_lines: List[str] = []
	        if host:
	            host_info_lines.append(f"Host name: {host}")
	        if ip:
	            host_info_lines.append(f"IP address: {ip}")
	        if mac:
	            host_info_lines.append(f"MAC address: {mac}")
	        host_info = "\n".join(host_info_lines).strip()

	        qnum = 1
	        if dt:
	            out2[(None, qnum)] = Answer(level=None, number=qnum, answer=dt, explanation="")
	            qnum += 1
	        if host_info:
	            out2[(None, qnum)] = Answer(level=None, number=qnum, answer=host_info, explanation="")
	            qnum += 1
	        if summary:
	            out2[(None, qnum)] = Answer(level=None, number=qnum, answer=summary, explanation="")
	            qnum += 1
	        if recs:
	            out2[(None, qnum)] = Answer(level=None, number=qnum, answer=recs, explanation="")
	            qnum += 1
	        # Also emit IOCs if available (newer exercise format).
	        if iocs:
	            out2[(None, qnum)] = Answer(level=None, number=qnum, answer=iocs, explanation="")
	            qnum += 1

	        # Guard: require at least 2 to be confident.
	        if len(out2) >= 2:
	            return out2
	        return {}

    def _parse_host_info_description_answers() -> Dict[Tuple[Optional[int], int], Answer]:
        """Parse common MTA 'host info + description' answer PDFs.

        Many answer PDFs are structured as:
          HOST INFORMATION: (or 'Affected host:')
            IP address: ...
            MAC address: ...
            Host name: ...
          Description of malicious activity: ...
          Indicators of compromise: ...

        We emit answers that align to common 'report should include' questions.
        """
        # Guard: must have TRAFFIC ANALYSIS and ANSWERS in the header.
        head = "\n".join([ln.strip() for ln in lines[:50] if (ln or "").strip()])
        head_u = head.upper()
        if "TRAFFIC ANALYSIS" not in head_u or "ANSWER" not in head_u:
            return {}

        low = text.lower()
        # Must have at least host info or IP address pattern.
        if ("host information" not in low and "affected host" not in low and
            "ip address:" not in low and "host ip address:" not in low):
            return {}

        def _norm(s: str) -> str:
            return re.sub(r"\s+", " ", (s or "").strip())

        # Extract key-value pairs from the entire text.
        kv_re = re.compile(r"^\s*(?:[\u2022\-\*]\s*)?([^:]{3,80}?)\s*:\s*(.+?)\s*$")
        kv: Dict[str, str] = {}
        for ln in lines:
            m = kv_re.match(ln or "")
            if not m:
                continue
            k = _norm(m.group(1) or "")
            v = _norm(m.group(2) or "")
            if not k or not v:
                continue
            kv.setdefault(k.lower(), v)

        def _kv_get(*keys: str) -> str:
            for k in keys:
                v = kv.get(k.lower())
                if v:
                    return v
            return ""

        ip = _kv_get("IP address", "Host IP address", "Infected computer's IP address")
        mac = _kv_get("MAC address", "Host MAC address", "Infected computer's MAC address")
        host = _kv_get("Host name", "Hostname", "Infected computer's host name", "Computer name")
        user = _kv_get("User name", "Username", "User's name", "User")

        # Look for description/summary blocks.
        desc_match = re.search(
            r"(?:Description\s+of\s+(?:malicious\s+)?activity|Brief\s+description|What\s+happened)\s*[:\-]?\s*(.{30,1500}?)(?=\n\s*(?:Indicator|IOC|Associated|Malware|SHA|URL|DETAILS|HINTS|$))",
            text, re.IGNORECASE | re.DOTALL
        )
        description = _norm(desc_match.group(1)) if desc_match else ""

        # Look for IOCs block.
        ioc_match = re.search(
            r"Indicators?\s+of\s+compromise[:\s]*\(?IOCs?\)?[:\s]*(.{20,2000}?)(?=\n\s*(?:DETAILS|HINTS|$)|\Z)",
            text, re.IGNORECASE | re.DOTALL
        )
        iocs = _norm(ioc_match.group(1)) if ioc_match else ""
        # If no IOC block, try to extract from any SHA256/IP patterns.
        if not iocs:
            sha_matches = re.findall(r"\b[a-fA-F0-9]{64}\b", text)
            if sha_matches:
                iocs = "SHA256 hashes:\n" + "\n".join(sha_matches[:5])

        out2: Dict[Tuple[Optional[int], int], Answer] = {}
        qnum = 1
        # Build host info block.
        host_info_lines: List[str] = []
        if ip:
            host_info_lines.append(f"IP address: {ip}")
        if mac:
            host_info_lines.append(f"MAC address: {mac}")
        if host:
            host_info_lines.append(f"Host name: {host}")
        if user:
            host_info_lines.append(f"User name: {user}")
        host_info = "\n".join(host_info_lines).strip()

        if host_info:
            out2[(None, qnum)] = Answer(level=None, number=qnum, answer=host_info, explanation="")
            qnum += 1
        if description:
            out2[(None, qnum)] = Answer(level=None, number=qnum, answer=description, explanation="")
            qnum += 1
        if iocs:
            out2[(None, qnum)] = Answer(level=None, number=qnum, answer=iocs, explanation="")
            qnum += 1

        # Require at least 2 answers for confidence.
        if len(out2) >= 2:
            return out2
        return {}

    def _parse_qa_colon_format() -> Dict[Tuple[Optional[int], int], Answer]:
        """Parse 'Q: question\\nA: answer' format found in some PDFs.

        Example:
          Q: What happened?
          A: The user visited a malicious website...
        """
        # Guard: must have TRAFFIC ANALYSIS and ANSWER in the header.
        head = "\n".join([ln.strip() for ln in lines[:40] if (ln or "").strip()])
        head_u = head.upper()
        if "TRAFFIC ANALYSIS" not in head_u or "ANSWER" not in head_u:
            return {}

        # Look for Q:/A: patterns.
        qa_pairs: List[Tuple[str, str]] = []
        q_re = re.compile(r"^\s*Q\s*[:\-]\s*(.+)$", re.IGNORECASE)
        a_re = re.compile(r"^\s*A\s*[:\-]\s*(.+)$", re.IGNORECASE)

        current_q: Optional[str] = None
        current_a_lines: List[str] = []

        for ln in lines:
            s = (ln or "").rstrip()
            qm = q_re.match(s)
            am = a_re.match(s)

            if qm:
                # Save previous Q/A pair.
                if current_q and current_a_lines:
                    qa_pairs.append((current_q, "\n".join(current_a_lines).strip()))
                current_q = (qm.group(1) or "").strip()
                current_a_lines = []
            elif am:
                if current_q:
                    current_a_lines.append((am.group(1) or "").strip())
            elif current_q and current_a_lines:
                # Continue collecting answer lines until next Q: or empty.
                s2 = s.strip()
                if s2 and not re.match(r"^(HINT|NOTE|DETAIL)", s2, re.I):
                    current_a_lines.append(s2)

        # Don't forget the last pair.
        if current_q and current_a_lines:
            qa_pairs.append((current_q, "\n".join(current_a_lines).strip()))

        if len(qa_pairs) < 1:
            return {}

        out2: Dict[Tuple[Optional[int], int], Answer] = {}
        for i, (q, a) in enumerate(qa_pairs, start=1):
            if a:
                out2[(None, i)] = Answer(level=None, number=i, answer=a, explanation="")

        if len(out2) >= 1:
            return out2
        return {}

    def _parse_isc_end_of_year_quiz_family_answers() -> Dict[Tuple[Optional[int], int], Answer]:
        """Parse ISC 'End of Year Traffic Analysis Quiz' answers as 1 answer per pcap.

        The PDF is structured:
          SCENARIO: ... list of N pcaps
          ANSWERS:
            <pcap-01>
              narrative + IOCs
            <pcap-02>
              ...

        We emit N answers where answer=<malware family> and explanation is a trimmed
        excerpt (including IOCs) for that pcap.
        """

        head = "\n".join([ln.strip() for ln in lines[:60] if (ln or "").strip()])
        head_u = head.upper()
        if "TRAFFIC ANALYSIS QUIZ" not in head_u or "SCENARIO" not in head_u or "MALWARE FAMILY" not in head_u:
            return {}

        pcap_re = re.compile(
            r"\b([0-9]{4}-[0-9]{2}-[0-9]{2}-traffic-analysis-quiz-[0-9]{2}\.pcap)\b",
            re.IGNORECASE,
        )

        try:
            scen_idx = next(i for i, ln in enumerate(lines) if (ln or "").strip().upper().startswith("SCENARIO"))
        except StopIteration:
            return {}

        try:
            ans_idx = next(i for i, ln in enumerate(lines) if generic_ans_re.match((ln or "").strip()))
        except StopIteration:
            return {}

        pcaps: List[str] = []
        seen = set()
        for ln in lines[scen_idx:ans_idx]:
            for m in pcap_re.finditer(ln or ""):
                p = (m.group(1) or "").strip()
                if p and p not in seen:
                    seen.add(p)
                    pcaps.append(p)
        if len(pcaps) < 3:
            return {}

        pcap_to_qnum = {p: i + 1 for i, p in enumerate(pcaps)}
        pcap_set = set(pcaps)

        # Split into per-PCAP blocks.
        blocks: Dict[str, List[str]] = {p: [] for p in pcaps}
        cur: Optional[str] = None
        for ln in lines[ans_idx + 1 :]:
            s = (ln or "").strip()
            if not s:
                continue
            if _is_noise_line(s):
                continue

            # Start of a new pcap section.
            if s in pcap_set:
                cur = s
                continue

            if cur is None:
                continue
            blocks[cur].append(s)

        family_re = re.compile(r"\btraffic\s+from\s+an?\s+(.+?)\s+infection\b", re.IGNORECASE)

        out2: Dict[Tuple[Optional[int], int], Answer] = {}
        for p in pcaps:
            sec = blocks.get(p) or []
            joined = " ".join(sec)
            fam = ""
            m = family_re.search(joined)
            if m:
                fam = (m.group(1) or "").strip()
                # Normalize: drop common trailing qualifiers.
                fam = re.sub(r"\bmalware\b", "", fam, flags=re.IGNORECASE).strip()
                fam = re.split(r"\s+with\s+", fam, maxsplit=1, flags=re.IGNORECASE)[0].strip()
                fam = re.sub(r"\s+", " ", fam).strip().rstrip(" .,:;\t")

            if not fam:
                continue

            expl = "\n".join(sec).strip()
            if len(expl) > 1400:
                expl = expl[:1400].rstrip() + "..."
            out2[(None, pcap_to_qnum[p])] = Answer(level=None, number=pcap_to_qnum[p], answer=fam, explanation=expl)

        # Guard: require multiple parsed families to avoid accidental triggering.
        if len(out2) >= 3:
            return out2
        return {}

    def _parse_isc_quiz_style_answers() -> Dict[Tuple[Optional[int], int], Answer]:
        """Parse ISC "traffic analysis quiz" PDFs that use bullet questions + bullet answers.

        These PDFs often contain:
          QUESTIONS:
            • ...
          ANSWERS:
            • IP address: ...
            ...
            Date/time of the infection:
              • ...
            Which two IP addresses ... "Internet Widgets Pty" ...?
              • ...
        """

        upper_head = "\n".join([ln.strip() for ln in lines[:40] if ln.strip()]).upper()
        if "TRAFFIC ANALYSIS QUIZ" not in upper_head or "ANSWERS" not in upper_head:
            return {}

        try:
            ans_idx = next(i for i, ln in enumerate(lines) if generic_ans_re.match((ln or "").strip()))
        except StopIteration:
            return {}

        bullet_kv_re = re.compile(r"^\s*[\u2022\-\*]\s*([^:]{2,50})\s*:\s*(.+?)\s*$")
        bullet_item_re = re.compile(r"^\s*[\u2022\-\*]\s*(.+?)\s*$")

        def norm(s: str) -> str:
            return re.sub(r"\s+", " ", (s or "").strip().lower())

        key_map = {
            "ip address": 1,
            "mac address": 2,
            "host name": 3,
            "hostname": 3,
            "user account name": 4,
            "windows user account name": 4,
            "user name": 4,
            "username": 4,
        }

        def header_to_qnum(h: str) -> Optional[int]:
            h2 = norm(h)
            if "date/time" in h2 or ("date" in h2 and "time" in h2):
                return 5
            if "sha256" in h2:
                return 6
            if "internet" in h2 and ("widget" in h2 or "widgit" in h2):
                return 7
            if "based on the alert" in h2 or "type of malware" in h2:
                return 8
            return None

        ans_lines_by_qnum: Dict[int, List[str]] = {}
        expl_lines_by_qnum: Dict[int, List[str]] = {}
        current_qnum: Optional[int] = None
        pending_header: List[str] = []

        for ln in lines[ans_idx + 1 :]:
            s = (ln or "").strip()
            if not s:
                continue
            if _is_noise_line(s):
                continue

            m_kv = bullet_kv_re.match(s)
            if m_kv:
                k = norm(m_kv.group(1))
                v = (m_kv.group(2) or "").strip()
                qn = key_map.get(k)
                if qn is not None and v:
                    ans_lines_by_qnum.setdefault(qn, []).append(v)
                    # Key-value bullets are standalone answers.
                    current_qnum = None
                    pending_header = []
                    continue

            m_b = bullet_item_re.match(s)
            if m_b:
                item = (m_b.group(1) or "").strip()
                if pending_header and current_qnum is None:
                    hdr = " ".join(pending_header).strip()
                    pending_header = []
                    current_qnum = header_to_qnum(hdr)
                if current_qnum is not None and item:
                    ans_lines_by_qnum.setdefault(current_qnum, []).append(item)
                continue

            # Non-bullet line: could be a wrapped header/question prompt or a note.
            if current_qnum is not None:
                if s.lower().startswith("note"):
                    expl_lines_by_qnum.setdefault(current_qnum, []).append(s)
                else:
                    # Sometimes the prompt is wrapped across lines before the bullet list starts.
                    pending_header.append(s)
                continue

            # No active section: accumulate potential header lines until the next bullet.
            pending_header.append(s)
            # If the header becomes too large, keep only the most recent portion.
            if len(pending_header) > 4:
                pending_header = pending_header[-4:]

        out2: Dict[Tuple[Optional[int], int], Answer] = {}
        for qn, alines in sorted(ans_lines_by_qnum.items()):
            ans = "\n".join([x for x in alines if (x or "").strip()]).strip()
            expl = "\n".join([x for x in expl_lines_by_qnum.get(qn, []) if (x or "").strip()]).strip()
            if ans:
                out2[(None, qn)] = Answer(level=None, number=qn, answer=ans, explanation=expl)
        # Require at least a couple of mapped answers to avoid false positives.
        if len(out2) >= 2:
            return out2
        return {}


    rep = _parse_incident_report_style_answers()
    if rep:
        return rep

    host_desc = _parse_host_info_description_answers()
    if host_desc:
        return host_desc

    qa_colon = _parse_qa_colon_format()
    if qa_colon:
        return qa_colon

    isc_eoy = _parse_isc_end_of_year_quiz_family_answers()
    if isc_eoy:
        return isc_eoy

    isc = _parse_isc_quiz_style_answers()
    if isc:
        return isc

    def _parse_html_label_colon_answers() -> Dict[Tuple[Optional[int], int], Answer]:
        """Parse common HTML answer pages where prompts end with ':' followed by list items.

        Example (from linked answer pages):
          ANSWERS
          The infected computer's host name:
          Leonardo-PC
          The infected computer's MAC address:
          80:c1:...

        These pages usually have no numeric question IDs, so we auto-number in order.
        """

        try:
            ans_idx = next(i for i, ln in enumerate(lines) if generic_ans_re.match((ln or "").strip()))
        except StopIteration:
            return {}

        def is_prompt(s: str) -> bool:
            s2 = (s or "").strip()
            if not s2:
                return False
            if s2.upper().startswith("HINT"):
                return False
            if _is_noise_line(s2):
                return False
            if not (s2.endswith(":") or s2.endswith("?")):
                return False
            core = s2[:-1].strip()
            if len(core) < 8:
                return False
            if not re.search(r"[A-Za-z]", core):
                return False
            # Avoid treating pure IOCs as prompts.
            if IOC_IP_RE.fullmatch(core) or IOC_MD5_RE.fullmatch(core) or IOC_SHA1_RE.fullmatch(core) or IOC_SHA256_RE.fullmatch(core):
                return False
            if core.upper() in {"NOTICE", "TRAFFIC", "ANSWERS", "HINTS"}:
                return False
            return True

        # Quick guard: only trigger if we see at least 2 prompt-like lines after ANSWERS.
        prompt_count = 0
        for ln in lines[ans_idx + 1 : ans_idx + 350]:
            s = (ln or "").strip()
            if not s:
                continue
            if s.upper().startswith("HINT"):
                break
            if is_prompt(s):
                prompt_count += 1
            if prompt_count >= 2:
                break
        if prompt_count < 2:
            return {}

        out2: Dict[Tuple[Optional[int], int], Answer] = {}
        cur_qnum: Optional[int] = None
        cur_vals: List[str] = []
        next_qnum = 1

        def flush2() -> None:
            nonlocal cur_qnum, cur_vals
            if cur_qnum is None:
                return
            ans_txt = "\n".join([v for v in cur_vals if (v or "").strip()]).strip()
            if ans_txt:
                out2[(None, cur_qnum)] = Answer(level=None, number=cur_qnum, answer=ans_txt, explanation="")
            cur_qnum = None
            cur_vals = []

        for ln in lines[ans_idx + 1 :]:
            s = (ln or "").strip()
            if not s:
                continue
            if s.upper().startswith("HINT"):
                break
            if _is_noise_line(s):
                continue

            if is_prompt(s):
                flush2()
                cur_qnum = next_qnum
                next_qnum += 1
                cur_vals = []
                continue

            if cur_qnum is not None:
                cur_vals.append(s)

        flush2()

        # Require multiple answers to avoid false positives.
        if len(out2) >= 2:
            return out2
        return {}

    html2 = _parse_html_label_colon_answers()
    if html2:
        return html2

    def flush_current() -> None:
        nonlocal current_qnum, current_answer_lines, current_expl_lines, current_inline, mode, inline_collect
        if current_qnum is None:
            return

        ans_lines = [s for s in current_answer_lines if (s or "").strip()]
        expl_lines = [s for s in current_expl_lines if (s or "").strip() or s == ""]

        # Drop obvious boilerplate from explanations.
        expl_lines = [ln for ln in expl_lines if not _is_noise_line(ln)]

        # Inline-style sections sometimes accumulate commentary into the "answer" bucket.
        # If we have a concise first line and then large/NOTE/header lines, split them into explanation.
        if not expl_lines and len(ans_lines) > 1:
            first = (ans_lines[0] or "").strip()
            moved: List[str] = []
            kept: List[str] = [first] if first else []
            for ln in ans_lines[1:]:
                ln2 = (ln or "").strip()
                if not ln2:
                    continue
                if ln2.upper().startswith("NOTE") or _is_noise_line(ln2) or len(ln2) > 120:
                    moved.append(ln2)
                else:
                    kept.append(ln2)
            if moved and kept:
                ans_lines = kept
                expl_lines = moved

        ans = "\n".join(ans_lines).strip()
        expl = "\n".join([s for s in expl_lines if s is not None]).strip()
        if not ans and not expl and current_inline.strip() and _looks_like_inline_answer_value(current_inline):
            # Fallback for answer keys that use: "1) <answer>" without Answer:/Explanation:
            ans = current_inline.strip()
        # Some answer PDFs repeat question blocks (e.g., "LEVEL 2 QUESTIONS") after
        # a previous answer section; avoid overwriting already-parsed answers.
        out.setdefault(
            (current_level, current_qnum),
            Answer(level=current_level, number=current_qnum, answer=ans, explanation=expl),
        )
        current_qnum = None
        current_answer_lines = []
        current_expl_lines = []
        current_inline = ""
        mode = None
        inline_collect = False

    for ln in lines:
        ln_stripped = ln.strip()
        if not ln_stripped:
            # Keep paragraph breaks inside explanation.
            if mode == "explanation":
                current_expl_lines.append("")
            continue

        lm = level_ans_re.match(ln_stripped)
        if lm:
            flush_current()
            current_level = int(lm.group(1))
            in_answers = True
            section_inline_default = False
            continue

        if generic_ans_re.match(ln_stripped):
            flush_current()
            current_level = None
            in_answers = True
            section_inline_default = False
            continue

        # Per-PCAP answer blocks: treat the filename label as the start of an inline-by-default answer section.
        if (
            not in_answers
            and pcap_label_re.match(ln_stripped)
            and "://" not in ln_stripped
        ):
            flush_current()
            current_level = None
            in_answers = True
            section_inline_default = True
            continue

        # BASIC / ADVANCED / EXTRA answer sections (inline-by-default)
        if basic_ans_re.match(ln_stripped):
            flush_current()
            current_level = 1
            in_answers = True
            section_inline_default = True
            continue
        if adv_ans_re.match(ln_stripped) or ans_to_adv_re.match(ln_stripped):
            flush_current()
            current_level = 2
            in_answers = True
            section_inline_default = True
            continue
        if extra_ans_re.match(ln_stripped) or ans_to_extra_re.match(ln_stripped):
            flush_current()
            current_level = 3
            in_answers = True
            section_inline_default = True
            continue

        # Many MTA answer PDFs interleave question sections between answer sections.
        # When we hit a QUESTIONS header, stop parsing until the next ANSWERS header.
        lq = level_q_re.match(ln_stripped)
        if lq or generic_q_re.match(ln_stripped) or basic_q_re.match(ln_stripped) or adv_q_re.match(ln_stripped) or extra_q_re.match(ln_stripped):
            flush_current()
            in_answers = False
            mode = None
            continue

        if not in_answers:
            continue

        qm = q_re.match(ln_stripped)
        if qm:
            flush_current()
            current_qnum = int(qm.group(1))
            remainder = (qm.group(2) or qm.group(3) or "").strip()
            current_inline = remainder
            mode = None
            inline_collect = section_inline_default

            # If the answer is actually on the same line (common for some one-liner keys),
            # capture it immediately in inline mode.
            if inline_collect and remainder and _looks_like_inline_answer_value(remainder):
                current_answer_lines.append(remainder)
                current_inline = ""
            continue

        am = ans_re.match(ln)
        if am and current_qnum is not None:
            mode = "answer"
            inline_collect = False
            if am.group(1).strip():
                current_answer_lines.append(am.group(1).strip())
            continue

        em = expl_re.match(ln)
        if em and current_qnum is not None:
            mode = "explanation"
            inline_collect = False
            if em.group(1).strip():
                current_expl_lines.append(em.group(1).strip())
            continue

        if current_qnum is not None:
            # Heuristic: if we haven't hit Answer: yet, ignore question-repeat lines.
            if mode is None:
                if inline_collect:
                    # In inline-style answer sections, treat NOTE/header/long lines as explanation once
                    # we already captured something answer-like.
                    if current_answer_lines and (
                        ln_stripped.upper().startswith("NOTE")
                        or _is_noise_line(ln_stripped)
                        or len(ln_stripped) > 120
                    ):
                        current_expl_lines.append(ln_stripped)
                    else:
                        current_answer_lines.append(ln_stripped)
                continue
            if mode == "answer":
                current_answer_lines.append(ln_stripped)
            elif mode == "explanation":
                current_expl_lines.append(ln_stripped)

    flush_current()
    return out


def iocs_from_text(s: str) -> Dict[str, List[str]]:
    def uniq(xs: List[str]) -> List[str]:
        seen = set()
        out2 = []
        for x in xs:
            if x not in seen:
                seen.add(x)
                out2.append(x)
        return out2

    return {
        "ips": uniq(IOC_IP_RE.findall(s)),
        "urls": uniq(IOC_URL_RE.findall(s)),
        "md5": uniq([m.lower() for m in IOC_MD5_RE.findall(s)]),
        "sha1": uniq([m.lower() for m in IOC_SHA1_RE.findall(s)]),
        "sha256": uniq([m.lower() for m in IOC_SHA256_RE.findall(s)]),
    }


def find_answer_docs(exercise_dir: Path, *, broad: bool = False) -> List[Path]:
    """Return candidate answer documents for an exercise directory.

    When broad=False (default) we prefer precision (fewer docs).
    When broad=True we include more extracted text-like files as a last-resort.
    """
    candidates: List[Path] = []
    # 1) Extracted assets (often contains the answer PDF)
    assets_extracted = exercise_dir / "assets_extracted"
    if assets_extracted.exists():
        for p in assets_extracted.rglob("*"):
            if not p.is_file():
                continue
            name = p.name.lower()
            ext = p.suffix.lower()
            if ext in {".pdf", ".txt", ".log", ".html", ".htm"}:
                if broad or any(k in name for k in ["answer", "answers", "solution", "key"]):
                    candidates.append(p)

    # 1b) Non-zip assets sometimes include answer keys directly (without needing extraction).
    assets_dir = exercise_dir / "assets"
    if assets_dir.exists():
        for p in assets_dir.glob("*"):
            if not p.is_file():
                continue
            ext = p.suffix.lower()
            if ext not in {".pdf", ".txt", ".log", ".html", ".htm"}:
                continue
            name = p.name.lower()
            if broad or any(k in name for k in ["answer", "answers", "solution", "key"]):
                candidates.append(p)

    # 2) Linked pages (some exercises publish answers in index2.html etc.)
    linked_pages = exercise_dir / "linked_pages"
    if linked_pages.exists():
        for p in linked_pages.glob("*.html"):
            candidates.append(p)

    # 3) Last resort: the page itself sometimes includes answers.
    if broad:
        page_html = exercise_dir / "page.html"
        if page_html.exists():
            candidates.append(page_html)

    # Prefer PDFs first (usually best structured), then HTML, then TXT
    def score(p: Path) -> Tuple[int, int]:
        ext = p.suffix.lower()
        pri = {".pdf": 0, ".html": 1, ".htm": 1, ".txt": 2, ".log": 2}.get(ext, 9)
        # Slightly prefer files with 'answer' in basename.
        bonus = 0 if "answer" in p.name.lower() else 1
        return (pri, bonus)

    return sorted(list(dict.fromkeys(candidates)), key=score)


def load_metadata_title(exercise_dir: Path) -> str:
    meta = exercise_dir / "metadata.json"
    if not meta.exists():
        return exercise_dir.name
    try:
        data = json.loads(_safe_read_text(meta))
        title = data.get("title") or data.get("page_title") or exercise_dir.name
        date = data.get("date")
        if date:
            return f"{date} - {title}"
        return str(title)
    except Exception:
        return exercise_dir.name


def make_example(title: str, q: Question, a: Answer) -> dict:
    user = (
        f"MTA training exercise: {title}\n"
        f"Question (Level {q.level if q.level is not None else 'N/A'} / #{q.number}): {q.text}\n"
        "Provide the answer and a brief explanation."
    )
    payload = {
        "answer": a.answer.strip(),
        "explanation": a.explanation.strip(),
        "iocs": iocs_from_text("\n".join([a.answer, a.explanation])),
    }
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT_QA},
            {"role": "user", "content": user},
            {"role": "assistant", "content": json.dumps(payload, ensure_ascii=False)},
        ]
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--pages-dir",
        default=str(REPO_ROOT / "finetuning" / "data" / "raw" / "training_exercises" / "pages"),
        help="Root pages directory (default: finetuning/data/raw/training_exercises/pages)",
    )
    ap.add_argument(
        "--out",
        default=str(REPO_ROOT / "finetuning" / "data" / "training" / "mta_qa.jsonl"),
        help="Output JSONL path",
    )
    ap.add_argument("--limit", type=int, default=0, help="Limit exercises processed (0 = no limit)")
    ap.add_argument(
        "--include-unmatched",
        action="store_true",
        help="Also emit questions without a parsed answer (assistant answer/explanation empty)",
    )
    ap.add_argument(
        "--report",
        nargs="?",
        const="__AUTO__",
        default="",
        help=(
            "Write a per-exercise JSONL report. Optionally provide a path; "
            "if omitted, a default path derived from --out is used."
        ),
    )
    ap.add_argument(
        "--report-max-docs",
        type=int,
        default=40,
        help="Max number of attempted docs recorded per exercise in --report output",
    )
    args = ap.parse_args()

    pages_dir = Path(args.pages_dir)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    report_path: Optional[Path] = None
    if str(args.report).strip():
        if args.report == "__AUTO__":
            report_path = out_path.with_name(out_path.stem + "_skip_report.jsonl")
        else:
            report_path = Path(str(args.report))
        report_path.parent.mkdir(parents=True, exist_ok=True)

    exercise_dirs = [p for p in pages_dir.iterdir() if p.is_dir()]
    exercise_dirs.sort()
    if args.limit and args.limit > 0:
        exercise_dirs = exercise_dirs[: args.limit]

    written = 0
    skipped_no_answers = 0

    # Report stats (only used when --report is enabled)
    report_skipped_by_reason: Counter[str] = Counter()
    report_total_exercises = 0

    report_ctx = report_path.open("w", encoding="utf-8") if report_path else nullcontext(None)

    with report_ctx as report_f, out_path.open("w", encoding="utf-8") as f:
        for ex_dir in exercise_dirs:
                report_total_exercises += 1
                page_html = ex_dir / "page.html"

                title = load_metadata_title(ex_dir)
                report_entry: dict = {
                    "exercise_dir": to_repo_rel(ex_dir),
                    "slug": ex_dir.name,
                    "title": title,
                }

                if not page_html.exists():
                    report_entry.update(
                        {
                            "status": "skipped",
                            "skip_reason": "missing_page_html",
                            "candidate_docs_initial": [],
                            "candidate_docs_broad": [],
                            "attempts": [],
                            "counts": {
                                "questions_parsed": 0,
                                "answers_parsed": 0,
                                "examples_emitted": 0,
                            },
                        }
                    )
                    if report_f:
                        report_f.write(json.dumps(report_entry, ensure_ascii=False) + "\n")
                        report_skipped_by_reason["missing_page_html"] += 1
                    continue

                # Collect questions from page.html and (when needed) from answer docs.
                questions_map: Dict[Tuple[Optional[int], int], Question] = {}
                question_parse_error: Optional[str] = None
                try:
                    for q in parse_questions_from_page(page_html):
                        questions_map.setdefault((q.level, q.number), q)
                except Exception as e:
                    question_parse_error = f"{type(e).__name__}: {e}"[:400]

                answer_docs_initial = find_answer_docs(ex_dir)
                report_entry["candidate_docs_initial"] = [to_repo_rel(p) for p in answer_docs_initial]

                answers_map: Dict[Tuple[Optional[int], int], Answer] = {}
                attempted_docs: set[str] = set()
                attempts: List[dict] = []
                attempts_truncated = False

                extracted_ok = 0
                extracted_failed = 0
                extracted_any_text = False

                def _record_attempt(att: dict) -> None:
                    nonlocal attempts_truncated
                    if not report_f:
                        return
                    if len(attempts) < int(args.report_max_docs):
                        attempts.append(att)
                    else:
                        attempts_truncated = True

                def parse_answer_doc(doc: Path) -> None:
                    nonlocal answers_map, questions_map, extracted_ok, extracted_failed, extracted_any_text
                    doc_key = str(doc)
                    if doc_key in attempted_docs:
                        return
                    attempted_docs.add(doc_key)

                    att: dict = {
                        "path": to_repo_rel(doc),
                        "ext": doc.suffix.lower(),
                    }
                    try:
                        txt = extract_text_generic(doc)
                        extracted_any_text = True
                        extracted_ok += 1
                        att["extracted"] = True
                    except Exception as e:
                        extracted_failed += 1
                        att["extracted"] = False
                        att["error"] = f"{type(e).__name__}: {e}"[:600]
                        _record_attempt(att)
                        return

                    parsed = parse_answers_from_text(txt)
                    att["answers_parsed"] = len(parsed)
                    for k, v in parsed.items():
                        answers_map.setdefault(k, v)

                    # Some answer PDFs include the questions; use as a fallback.
                    if not questions_map and parsed:
                        qs = parse_questions_from_text(txt)
                        att["questions_parsed_from_doc"] = len(qs)
                        for q in qs:
                            questions_map.setdefault((q.level, q.number), q)

                    _record_attempt(att)

                for doc in answer_docs_initial:
                    parse_answer_doc(doc)

                answer_docs_broad: List[Path] = []
                # If we found no parseable answers, broaden our document search (txt/log/html/pdf).
                if not answers_map:
                    answer_docs_broad = find_answer_docs(ex_dir, broad=True)
                    for doc in answer_docs_broad:
                        if doc in answer_docs_initial:
                            continue
                        parse_answer_doc(doc)
                report_entry["candidate_docs_broad"] = [to_repo_rel(p) for p in answer_docs_broad]

                # Determine if this exercise is skipped and why.
                answers_parsed = len(answers_map)
                questions_parsed = len(questions_map)

                skip_reason: Optional[str] = None
                skipped = False

                total_candidates = len(set(report_entry["candidate_docs_initial"]) | set(report_entry["candidate_docs_broad"]))

                if answers_parsed == 0:
                    skipped_no_answers += 1
                    if total_candidates == 0:
                        skip_reason = "no_candidate_docs"
                    elif not extracted_any_text or extracted_ok == 0:
                        skip_reason = "extraction_failed"
                    else:
                        skip_reason = "docs_found_but_zero_answers_parsed"
                    skipped = not bool(args.include_unmatched)
                elif questions_parsed == 0:
                    skip_reason = "answers_found_but_zero_questions_parsed"
                    skipped = not bool(args.include_unmatched)

                examples_emitted_this_ex = 0
                if not skipped:
                    def find_answer_for_question(q: Question) -> Optional[Answer]:
                        direct = answers_map.get((q.level, q.number))
                        if direct is not None:
                            return direct
                        # If level doesn't line up, only match by number when unambiguous.
                        matches = [a for (lvl, num), a in answers_map.items() if num == q.number]
                        if len(matches) == 1:
                            return matches[0]
                        return None

                    for key in sorted(
                        questions_map.keys(),
                        key=lambda t: ((t[0] is None), t[0] or 0, t[1]),
                    ):
                        q = questions_map[key]
                        ans = find_answer_for_question(q)
                        if ans is None:
                            if not args.include_unmatched:
                                continue
                            ans = Answer(level=q.level, number=q.number, answer="", explanation="")
                        ex = make_example(title=title, q=q, a=ans)
                        f.write(json.dumps(ex, ensure_ascii=False) + "\n")
                        written += 1
                        examples_emitted_this_ex += 1

                if report_f:
                    report_entry.update(
                        {
                            "status": "skipped" if skipped else "ok",
                            "skip_reason": skip_reason or "",
                            "question_parse_error": question_parse_error or "",
                            "attempts": attempts,
                            "attempts_truncated": attempts_truncated,
                            "counts": {
                                "questions_parsed": questions_parsed,
                                "answers_parsed": answers_parsed,
                                "examples_emitted": examples_emitted_this_ex,
                                "docs_candidates_total": total_candidates,
                                "docs_extracted_ok": extracted_ok,
                                "docs_extracted_failed": extracted_failed,
                            },
                        }
                    )
                    report_f.write(json.dumps(report_entry, ensure_ascii=False) + "\n")
                    if skipped:
                        report_skipped_by_reason[(skip_reason or "unknown")] += 1

    print(f"Wrote {written} Q&A examples to: {out_path}")
    if skipped_no_answers:
        print(f"Skipped {skipped_no_answers} exercises with no parsed answers")
    if report_path:
        print(f"Wrote skip report to: {report_path}")
        total_skipped = sum(report_skipped_by_reason.values())
        print(f"Total skipped exercises (all skip reasons): {total_skipped}")
        if report_skipped_by_reason:
            summary = ", ".join(
                f"{k}={v}" for k, v in sorted(report_skipped_by_reason.items(), key=lambda kv: (-kv[1], kv[0]))
            )
            print(f"Skip report summary (skipped exercises): {summary}")
        print(f"Report covered {report_total_exercises} exercises")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

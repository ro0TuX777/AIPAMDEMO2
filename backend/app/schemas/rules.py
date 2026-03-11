from pydantic import BaseModel, Field
from typing import Dict, List, Optional


class SuricataRuleItem(BaseModel):
    filename: str
    content: Optional[str] = None
    size_bytes: int
    updated_at: str


class SuricataRuleUpdate(BaseModel):
    content: str


# ── Parsed rule management ──────────────────────────────────────────────────


class ParsedRule(BaseModel):
    """A single parsed Suricata rule."""
    sid: int
    enabled: bool
    action: str  # alert, drop, pass, reject
    msg: str
    classtype: str = ""
    severity: int = 3  # 1=high, 2=medium, 3=low (from priority or classtype)
    protocol: str = ""
    src: str = ""
    dst: str = ""
    rev: int = 1
    references: List[str] = []
    raw: str  # original line
    line_number: int


class ParsedRuleListResponse(BaseModel):
    items: List[ParsedRule]
    total: int
    total_enabled: int
    total_disabled: int
    offset: int
    limit: int


class CategoryStats(BaseModel):
    name: str
    total: int
    enabled: int
    disabled: int


class RuleFileStats(BaseModel):
    filename: str
    total_rules: int
    enabled: int
    disabled: int
    categories: List[CategoryStats]


class ToggleRulesRequest(BaseModel):
    sids: List[int] = Field(default_factory=list, description="Specific SIDs to toggle")
    category: Optional[str] = Field(None, description="Toggle all rules in this category")
    enabled: bool = Field(..., description="True to enable, False to disable")

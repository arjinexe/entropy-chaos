"""
Core data models for Entropy framework.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime
import uuid


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class PersonaType(str, Enum):
    MALICIOUS_INSIDER   = "malicious_insider"
    IMPATIENT_CONSUMER  = "impatient_consumer"
    BOT_SWARM           = "bot_swarm"
    CONFUSED_USER       = "confused_user"
    PENETRATION_TESTER  = "penetration_tester"
    CUSTOM              = "custom"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class FindingType(str, Enum):
    LOGIC_ERROR         = "logic_error"
    RACE_CONDITION      = "race_condition"
    AUTH_BYPASS         = "auth_bypass"
    INJECTION           = "injection"
    CRASH               = "crash"
    DATA_LEAK           = "data_leak"
    BUSINESS_LOGIC      = "business_logic"
    PERFORMANCE         = "performance"
    IDOR                = "idor"
    SSRF                = "ssrf"
    XXE                 = "xxe"
    DESERIALIZATION     = "deserialization"


class RequestMethod(str, Enum):
    GET    = "GET"
    POST   = "POST"
    PUT    = "PUT"
    PATCH  = "PATCH"
    DELETE = "DELETE"


class TestStatus(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"


# ---------------------------------------------------------------------------
# API Schema Models
# ---------------------------------------------------------------------------

@dataclass
class APIParameter:
    name:     str
    location: str           # query | path | header | body
    type:     str           # string | integer | boolean | object | array
    required: bool = False
    schema:   Optional[Dict[str, Any]] = None
    example:  Optional[Any] = None


@dataclass
class APIEndpoint:
    path:        str
    method:      RequestMethod
    summary:     str = ""
    description: str = ""
    parameters:  List[APIParameter] = field(default_factory=list)
    request_body: Optional[Dict[str, Any]] = None
    responses:   Dict[str, Any] = field(default_factory=dict)
    tags:        List[str] = field(default_factory=list)
    security:    List[Dict[str, Any]] = field(default_factory=list)

    @property
    def uid(self) -> str:
        return f"{self.method.value}:{self.path}"


@dataclass
class APISchema:
    title:     str
    version:   str
    base_url:  str
    endpoints: List[APIEndpoint] = field(default_factory=list)
    security_schemes: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Attack Tree
# ---------------------------------------------------------------------------

@dataclass
class AttackVector:
    id:          str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    endpoint:    Optional[APIEndpoint] = None
    description: str = ""
    payload:     Dict[str, Any] = field(default_factory=dict)
    headers:     Dict[str, str] = field(default_factory=dict)
    expected_anomaly: str = ""
    persona_type: Optional[PersonaType] = None


@dataclass
class AttackNode:
    id:       str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name:     str = ""
    goal:     str = ""
    vectors:  List[AttackVector] = field(default_factory=list)
    children: List["AttackNode"] = field(default_factory=list)
    severity: Severity = Severity.MEDIUM


@dataclass
class AttackTree:
    root:     AttackNode = field(default_factory=AttackNode)
    created_at: datetime = field(default_factory=datetime.utcnow)

    def all_vectors(self) -> List[AttackVector]:
        """Flatten all attack vectors from the tree."""
        result: List[AttackVector] = []
        stack = [self.root]
        while stack:
            node = stack.pop()
            result.extend(node.vectors)
            stack.extend(node.children)
        return result


# ---------------------------------------------------------------------------
# Test Execution Models
# ---------------------------------------------------------------------------

@dataclass
class HTTPRequest:
    method:  str
    url:     str
    headers: Dict[str, str] = field(default_factory=dict)
    params:  Dict[str, Any] = field(default_factory=dict)
    body:    Optional[Any] = None
    sent_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class HTTPResponse:
    status_code:  int
    headers:      Dict[str, str] = field(default_factory=dict)
    body:         Optional[Any] = None
    latency_ms:   float = 0.0
    received_at:  datetime = field(default_factory=datetime.utcnow)
    error:        Optional[str] = None


@dataclass
class TestStep:
    step_number:  int
    description:  str
    request:      Optional[HTTPRequest] = None
    response:     Optional[HTTPResponse] = None
    assertions:   List[str] = field(default_factory=list)
    passed:       Optional[bool] = None


# ---------------------------------------------------------------------------
# Findings & Reports
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    id:           str = field(default_factory=lambda: str(uuid.uuid4()))
    type:         FindingType = FindingType.LOGIC_ERROR
    severity:     Severity = Severity.MEDIUM
    title:        str = ""
    description:  str = ""
    endpoint:     str = ""
    persona:      str = ""
    steps:        List[TestStep] = field(default_factory=list)
    evidence:     Dict[str, Any] = field(default_factory=dict)
    remediation:  str = ""
    discovered_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "endpoint": self.endpoint,
            "persona": self.persona,
            "remediation": self.remediation,
            "discovered_at": self.discovered_at.isoformat(),
            "reproducible_steps": [
                {
                    "step": s.step_number,
                    "description": s.description,
                    "request": {
                        "method": s.request.method,
                        "url": s.request.url,
                        "headers": s.request.headers,
                        "body": s.request.body,
                    } if s.request else None,
                    "response": {
                        "status_code": s.response.status_code,
                        "body": s.response.body,
                        "latency_ms": s.response.latency_ms,
                        "error": s.response.error,
                    } if s.response else None,
                }
                for s in self.steps
            ],
        }


@dataclass
class EntropyReport:
    id:          str = field(default_factory=lambda: str(uuid.uuid4()))
    target:      str = ""
    started_at:  datetime = field(default_factory=datetime.utcnow)
    finished_at: Optional[datetime] = None
    status:      TestStatus = TestStatus.PENDING
    findings:    List[Finding] = field(default_factory=list)
    stats:       Dict[str, Any] = field(default_factory=dict)

    def summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

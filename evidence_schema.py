"""
Evidence v2 Schema - Contrato C5-REAL para Flota de Ingeniería Inversa REA.
Garantiza el desacoplamiento entre hechos verificados (Territorio) e inferencias (Mapa).
100% Pure Python Standard Library (Zero External Dependencies).
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import json


class _SchemaBase:
    """Mixin compatible con API Pydantic v2 pero en Python stdlib puro (0 dependencias)."""

    def model_dump(self) -> Dict[str, Any]:
        return asdict(self)

    def model_dump_json(self, indent: Optional[int] = None) -> str:
        return json.dumps(self.model_dump(), indent=indent, ensure_ascii=False)


@dataclass
class MemoryOffset(_SchemaBase):
    start_addr: str
    end_addr: Optional[str] = None
    section: Optional[str] = None

    @classmethod
    def model_validate(cls, data: Dict[str, Any]) -> "MemoryOffset":
        if isinstance(data, cls):
            return data
        return cls(
            start_addr=data["start_addr"],
            end_addr=data.get("end_addr"),
            section=data.get("section"),
        )


@dataclass
class FunctionEvidence(_SchemaBase):
    memory_location: MemoryOffset
    pseudocode: str
    symbol_name: Optional[str] = None
    mangled_name: Optional[str] = None
    cfg_nodes: int = 0
    xrefs_in: List[str] = field(default_factory=list)
    xrefs_out: List[str] = field(default_factory=list)
    invariants_verified: List[str] = field(default_factory=list)
    unknowns: List[str] = field(default_factory=list)

    @classmethod
    def model_validate(cls, data: Dict[str, Any]) -> "FunctionEvidence":
        if isinstance(data, cls):
            return data
        return cls(
            symbol_name=data.get("symbol_name"),
            mangled_name=data.get("mangled_name"),
            memory_location=MemoryOffset.model_validate(data["memory_location"]),
            pseudocode=data["pseudocode"],
            cfg_nodes=data.get("cfg_nodes", 0),
            xrefs_in=list(data.get("xrefs_in", [])),
            xrefs_out=list(data.get("xrefs_out", [])),
            invariants_verified=list(data.get("invariants_verified", [])),
            unknowns=list(data.get("unknowns", [])),
        )


@dataclass
class IPCEvidence(_SchemaBase):
    channel: str
    direction: str
    sender_location: Optional[str] = None
    handler_location: Optional[str] = None
    payload_schema: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def model_validate(cls, data: Dict[str, Any]) -> "IPCEvidence":
        if isinstance(data, cls):
            return data
        return cls(
            channel=data["channel"],
            direction=data["direction"],
            sender_location=data.get("sender_location"),
            handler_location=data.get("handler_location"),
            payload_schema=dict(data.get("payload_schema", {})),
        )


@dataclass
class BinaryTriageReport(_SchemaBase):
    target_path: str
    sha256: str
    file_size_bytes: int
    architecture: str
    entropy_shannon: float
    is_packed: bool = False
    packer_type: Optional[str] = None
    imported_libraries: List[str] = field(default_factory=list)
    exported_symbols_count: int = 0
    triage_timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @classmethod
    def model_validate(cls, data: Dict[str, Any]) -> "BinaryTriageReport":
        if isinstance(data, cls):
            return data
        return cls(
            target_path=data["target_path"],
            sha256=data["sha256"],
            file_size_bytes=int(data["file_size_bytes"]),
            architecture=data["architecture"],
            entropy_shannon=float(data["entropy_shannon"]),
            is_packed=bool(data.get("is_packed", False)),
            packer_type=data.get("packer_type"),
            imported_libraries=list(data.get("imported_libraries", [])),
            exported_symbols_count=int(data.get("exported_symbols_count", 0)),
            triage_timestamp=str(
                data.get("triage_timestamp", datetime.now(timezone.utc).isoformat())
            ),
        )


@dataclass
class EvidenceEnvelopeV2(_SchemaBase):
    target: BinaryTriageReport
    native_functions: List[FunctionEvidence] = field(default_factory=list)
    ipc_channels: List[IPCEvidence] = field(default_factory=list)
    extracted_strings: List[str] = field(default_factory=list)
    clean_room_specification: Dict[str, Any] = field(default_factory=dict)
    falsification_verdict: Optional[str] = None

    @classmethod
    def model_validate(cls, data: Dict[str, Any]) -> "EvidenceEnvelopeV2":
        if isinstance(data, cls):
            return data
        return cls(
            target=BinaryTriageReport.model_validate(data["target"]),
            native_functions=[
                FunctionEvidence.model_validate(fn)
                for fn in data.get("native_functions", [])
            ],
            ipc_channels=[
                IPCEvidence.model_validate(ch) for ch in data.get("ipc_channels", [])
            ],
            extracted_strings=list(data.get("extracted_strings", [])),
            clean_room_specification=dict(data.get("clean_room_specification", {})),
            falsification_verdict=data.get("falsification_verdict"),
        )


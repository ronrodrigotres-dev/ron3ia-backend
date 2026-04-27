"""
remediation_router.py
RON3IA — Autorreparación controlada de configuraciones YAML
─────────────────────────────────────────────────────────────────
Integra tres capas:
  1. yaml-change-orchestrator  → Motor v3 (quirúrgico / round-trip)
  2. yaml-diff-analyzer        → Clasificación de riesgo del diff
  3. yaml-commit-executor.ps1  → Escritura + commit Git vía subprocess

Endpoints:
  POST /remediation/plan
  POST /remediation/execute
  GET  /remediation/status/{task_id}

Regla de Oro (execute):
  safe == true  AND  risk_level == "low"  AND  approved_by presente
"""

from __future__ import annotations

import difflib
import json
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from ruamel.yaml import YAML

# ─────────────────────────────────────────────────────────────────────────────
# Configuración del entorno
# ─────────────────────────────────────────────────────────────────────────────

# Ajusta esta ruta al directorio donde viven los docker-compose de RON3IA
COMPOSE_BASE_DIR = Path(__file__).parent / "configs"

# Ruta al script PowerShell executor
PS_EXECUTOR = Path(__file__).parent / "scripts" / "yaml-commit-executor.ps1"

# Detecta si PowerShell Core está disponible (Linux/Mac) o usa powershell.exe (Windows)
PS_BIN = "pwsh" if sys.platform != "win32" else "powershell.exe"

# Store en memoria de tareas — swap por Supabase en producción
# Esquema: { task_id: TaskRecord }
_task_store: dict[str, dict] = {}

router = APIRouter(prefix="/remediation", tags=["remediation"])


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic Schemas
# ─────────────────────────────────────────────────────────────────────────────

class AuditFinding(BaseModel):
    """Hallazgo que llega desde el módulo de auditoría de RON3IA."""
    service: str            = Field(..., example="auth-service")
    file: str               = Field(..., example="docker-compose.yml")
    finding_type: str       = Field(..., example="vulnerable_image")
    description: str        = Field(..., example="Imagen obsoleta detectada")
    yaml_path: str          = Field(..., example="services.auth-service.image")
    current_value: str      = Field(..., example="redis:5.0")
    recommended_value: str  = Field(..., example="redis:7.0-alpine")


class DiffAnalysis(BaseModel):
    safe: bool
    risk_level: str                      # "low" | "medium" | "high"
    changes_detected: list[dict]
    unexpected_changes: list[str]
    summary: str
    recommendation: str                  # "safe_to_apply" | "review_required" | "reject_change"


class PlanResponse(BaseModel):
    task_id: str
    action: str                          # siempre "preview"
    request: dict
    strategy: str
    line_patched: int | None
    diff: str
    current_value: str
    analysis: DiffAnalysis
    created_at: str


class ExecuteRequest(BaseModel):
    task_id: str    = Field(..., description="task_id obtenido de /plan")
    approved_by: str = Field(..., example="ron@ron3ia.cl")


class ExecuteResponse(BaseModel):
    task_id: str
    status: str                          # "success" | "rejected" | "error"
    commit_hash: str | None = None
    message: str
    executed_at: str


class TaskStatus(BaseModel):
    task_id: str
    phase: str                           # "planned" | "executing" | "done" | "failed"
    safe: bool | None = None
    risk_level: str | None = None
    commit_hash: str | None = None
    error: str | None = None
    created_at: str
    updated_at: str


# ─────────────────────────────────────────────────────────────────────────────
# Motor v3 — yaml-change-orchestrator (inline)
# ─────────────────────────────────────────────────────────────────────────────

_IDX_RE = re.compile(r'^(?P<key>[^\[]+)\[(?P<idx>\d+)\]$')


def _parse_segment(seg: str) -> tuple[str, int | None]:
    m = _IDX_RE.match(seg)
    return (m.group("key"), int(m.group("idx"))) if m else (seg, None)


def _resolve_path(data, parts: list[str]):
    """Devuelve (parent_node, leaf_key, current_value). leaf_key es str|int."""
    node = data
    for part in parts[:-1]:
        key, idx = _parse_segment(part)
        node = node[key]
        if idx is not None:
            node = node[idx]
    last_key, last_idx = _parse_segment(parts[-1])
    if last_idx is not None:
        parent = node[last_key]
        return parent, last_idx, parent[last_idx]
    return node, last_key, node[last_key]


def _is_scalar(v) -> bool:
    return not isinstance(v, (dict, list))


def _get_line_number(parent_node, leaf_key) -> int | None:
    if hasattr(parent_node, "lc") and leaf_key in parent_node.lc.data:
        return parent_node.lc.data[leaf_key][0]
    return None


def _surgical_map(lines, idx, key, old, new) -> list[str] | None:
    pat = re.compile(
        r'^(?P<indent>\s*)' + re.escape(key) +
        r'(?P<sep>:\s*)(?P<q>["\']?)' + re.escape(old) +
        r'(?P=q)(?P<tail>.*)$'
    )
    m = pat.match(lines[idx])
    if not m:
        return None
    q = m.group("q")
    patched = lines.copy()
    patched[idx] = m.group("indent") + key + m.group("sep") + q + new + q + m.group("tail") + "\n"
    return patched


def _surgical_list(lines, idx, old, new) -> list[str] | None:
    pat = re.compile(
        r'^(?P<indent>\s*-\s*)(?P<q>["\']?)' + re.escape(old) +
        r'(?P=q)(?P<tail>.*)$'
    )
    m = pat.match(lines[idx])
    if not m:
        return None
    q = m.group("q")
    patched = lines.copy()
    patched[idx] = m.group("indent") + q + new + q + m.group("tail") + "\n"
    return patched


def _run_orchestrator(finding: AuditFinding) -> dict[str, Any]:
    """
    Ejecuta el Motor v3 en modo preview.
    Devuelve un dict con: diff, strategy, line_patched, current_value, safe_structure
    Lanza ValueError si el path no existe o el archivo no se encuentra.
    """
    compose_path = COMPOSE_BASE_DIR / finding.file
    if not compose_path.exists():
        raise ValueError(f"Archivo no encontrado: {compose_path}")

    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.indent(mapping=2, sequence=4, offset=2)

    original_text = compose_path.read_text(encoding="utf-8")
    original_lines = original_text.splitlines(keepends=True)
    data = yaml.load(original_text)

    parts = finding.yaml_path.split(".")
    try:
        parent_node, leaf_key, current_value = _resolve_path(data, parts)
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError(f"Path inválido '{finding.yaml_path}': {exc}") from exc

    if str(current_value) != finding.current_value:
        raise ValueError(
            f"Valor actual en archivo ('{current_value}') no coincide "
            f"con hallazgo ('{finding.current_value}'). Archivo puede haber cambiado."
        )

    is_list_item = isinstance(leaf_key, int)
    scalar = _is_scalar(current_value)
    line_idx = _get_line_number(parent_node, leaf_key) if scalar else None

    strategy = "round-trip"
    patched_lines = None

    if scalar and line_idx is not None:
        strategy = "surgical-list" if is_list_item else "surgical-map"
        patched_lines = (
            _surgical_list(original_lines, line_idx, str(current_value), finding.recommended_value)
            if is_list_item else
            _surgical_map(original_lines, line_idx, str(leaf_key), str(current_value), finding.recommended_value)
        )
        if patched_lines is None:
            strategy = "round-trip"      # regex no coincidió, fallback

    if patched_lines is None:
        parent_node[leaf_key] = finding.recommended_value
        buf = StringIO()
        yaml.dump(data, buf)
        modified_text = buf.getvalue()
    else:
        modified_text = "".join(patched_lines)

    diff_lines = list(difflib.unified_diff(
        original_text.splitlines(keepends=True),
        modified_text.splitlines(keepends=True),
        fromfile=f"a/{finding.file}",
        tofile=f"b/{finding.file}",
        lineterm="",
    ))
    diff_str = "\n".join(diff_lines)

    return {
        "diff": diff_str,
        "strategy": strategy,
        "line_patched": (line_idx + 1) if line_idx is not None else None,
        "current_value": str(current_value),
        "modified_text": modified_text,    # solo usado en execute, no se expone en plan
    }


# ─────────────────────────────────────────────────────────────────────────────
# yaml-diff-analyzer (inline)
# ─────────────────────────────────────────────────────────────────────────────

def _analyze_diff(diff: str, expected_path: str | None = None) -> DiffAnalysis:
    """
    Implementa la lógica del skill yaml-diff-analyzer.
    Clasifica el riesgo y devuelve un DiffAnalysis.
    """
    changed_lines = [
        l for l in diff.splitlines()
        if l.startswith(("+", "-")) and not l.startswith(("---", "+++"))
    ]

    if not changed_lines:
        return DiffAnalysis(
            safe=False,
            risk_level="high",
            changes_detected=[],
            unexpected_changes=[],
            summary="El diff no contiene cambios detectables.",
            recommendation="reject_change",
        )

    removals = [l[1:].strip() for l in changed_lines if l.startswith("-")]
    additions = [l[1:].strip() for l in changed_lines if l.startswith("+")]

    # Empareja pares remove/add
    changes_detected = []
    for old, new in zip(removals, additions):
        # Normalizar: extraer clave si es un map key o list item
        key_match = re.match(r'^-?\s*([^:=]+)[=:]', old)
        key = key_match.group(1).strip() if key_match else old[:20]
        changes_detected.append({"before": old, "after": new, "key": key})

    # Cambios fuera del path esperado
    unexpected = []
    if expected_path:
        last_seg = expected_path.split(".")[-1]
        is_list_path = bool(re.search(r'\[\d+\]$', last_seg))
        if not is_list_path:
            # MAP key: buscar el nombre de clave en las líneas del diff
            leaf = last_seg
            for c in changes_detected:
                if leaf not in c["before"] and leaf not in c["after"]:
                    unexpected.append(c["before"])
        # Para list items ([n]) el path fue validado upstream por el orchestrator;
        # no hay nombre de clave YAML en la línea diff, solo el valor → sin inesperados.

    n_changes = len(changes_detected)
    has_structural = any(
        re.search(r'^\s{0,2}\S', c["before"]) for c in changes_detected
    )

    if n_changes == 1 and not unexpected:
        risk = "low"
        safe = True
        rec = "safe_to_apply"
        summary = f"Un único cambio esperado sobre '{changes_detected[0]['key']}'."
    elif n_changes <= 3 and not unexpected and not has_structural:
        risk = "medium"
        safe = False
        rec = "review_required"
        summary = f"{n_changes} cambios detectados. Revisar antes de aplicar."
    else:
        risk = "high"
        safe = False
        rec = "reject_change"
        summary = (
            f"{n_changes} cambios o cambios estructurales detectados. "
            + ("Cambios inesperados fuera del path. " if unexpected else "")
        )

    return DiffAnalysis(
        safe=safe,
        risk_level=risk,
        changes_detected=changes_detected,
        unexpected_changes=unexpected,
        summary=summary,
        recommendation=rec,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Helpers internos
# ─────────────────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _store_task(task_id: str, data: dict) -> None:
    _task_store[task_id] = {**data, "updated_at": _now()}


def _update_task(task_id: str, updates: dict) -> None:
    if task_id in _task_store:
        _task_store[task_id].update({**updates, "updated_at": _now()})


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/plan",
    response_model=PlanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Genera un plan de remediación con diff y análisis de riesgo",
)
async def plan_remediation(finding: AuditFinding) -> PlanResponse:
    """
    Recibe un hallazgo de auditoría, ejecuta el Motor v3 en modo simulación
    y devuelve el diff + análisis de riesgo. No escribe ningún archivo.
    """
    # 1. Ejecutar orchestrator (Motor v3)
    try:
        orch = _run_orchestrator(finding)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )

    # 2. Analizar diff
    analysis = _analyze_diff(orch["diff"], expected_path=finding.yaml_path)

    # 3. Construir task y persistir
    task_id = str(uuid.uuid4())
    created_at = _now()

    _store_task(task_id, {
        "phase": "planned",
        "finding": finding.model_dump(),
        "diff": orch["diff"],
        "modified_text": orch["modified_text"],
        "safe": analysis.safe,
        "risk_level": analysis.risk_level,
        "commit_hash": None,
        "error": None,
        "created_at": created_at,
    })

    return PlanResponse(
        task_id=task_id,
        action="preview",
        request={
            "file": finding.file,
            "path": finding.yaml_path,
            "new_value": finding.recommended_value,
        },
        strategy=orch["strategy"],
        line_patched=orch["line_patched"],
        diff=orch["diff"],
        current_value=orch["current_value"],
        analysis=analysis,
        created_at=created_at,
    )


@router.post(
    "/execute",
    response_model=ExecuteResponse,
    status_code=status.HTTP_200_OK,
    summary="Ejecuta la remediación si el plan es seguro y está aprobado",
)
async def execute_remediation(req: ExecuteRequest) -> ExecuteResponse:
    """
    REGLA DE ORO: solo procede si safe == true, risk_level == 'low'
    y existe approved_by.
    Invoca yaml-commit-executor.ps1 vía subprocess.
    """
    executed_at = _now()

    # 1. Recuperar task
    task = _task_store.get(req.task_id)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"task_id '{req.task_id}' no encontrado. Ejecuta /plan primero.",
        )

    if task["phase"] == "done":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"La tarea '{req.task_id}' ya fue ejecutada. Commit: {task.get('commit_hash')}",
        )

    # 2. Regla de Oro
    if not task["safe"]:
        _update_task(req.task_id, {"phase": "failed", "error": "safe == false"})
        return ExecuteResponse(
            task_id=req.task_id,
            status="rejected",
            message=f"Rechazado: el diff no es seguro (safe=false, risk={task['risk_level']}).",
            executed_at=executed_at,
        )

    if task["risk_level"] != "low":
        _update_task(req.task_id, {
            "phase": "failed",
            "error": f"risk_level={task['risk_level']} — se requiere 'low'",
        })
        return ExecuteResponse(
            task_id=req.task_id,
            status="rejected",
            message=f"Rechazado: risk_level='{task['risk_level']}'. Solo se ejecuta con risk_level='low'.",
            executed_at=executed_at,
        )

    # 3. Verificar que el executor existe
    if not PS_EXECUTOR.exists():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Script executor no encontrado: {PS_EXECUTOR}",
        )

    # 4. Escribir archivo modificado en disco (antes del commit)
    finding = task["finding"]
    compose_path = COMPOSE_BASE_DIR / finding["file"]
    _update_task(req.task_id, {"phase": "executing"})

    try:
        compose_path.write_text(task["modified_text"], encoding="utf-8")
    except OSError as exc:
        _update_task(req.task_id, {"phase": "failed", "error": f"Write error: {exc}"})
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error escribiendo el archivo: {exc}",
        )

    # 5. Invocar yaml-commit-executor.ps1
    ps_args = [
        PS_BIN, "-NonInteractive", "-File", str(PS_EXECUTOR),
        "-FilePath",   str(compose_path),
        "-CommitMsg",  f"fix({finding['service']}): {finding['description']} [approved_by={req.approved_by}]",
        "-ApprovedBy", req.approved_by,
        "-TaskId",     req.task_id,
    ]

    try:
        result = subprocess.run(
            ps_args,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        _update_task(req.task_id, {"phase": "failed", "error": "PowerShell timeout (60s)"})
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="El script PowerShell excedió el timeout de 60 segundos.",
        )
    except FileNotFoundError:
        _update_task(req.task_id, {"phase": "failed", "error": f"{PS_BIN} no encontrado en PATH"})
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"'{PS_BIN}' no está disponible. Instala PowerShell Core o ajusta PS_BIN.",
        )

    # 6. Parsear resultado del script
    if result.returncode != 0:
        error_detail = result.stderr.strip() or result.stdout.strip()
        _update_task(req.task_id, {"phase": "failed", "error": error_detail})
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"El executor falló (exit {result.returncode}): {error_detail}",
        )

    # El script debe imprimir el hash en stdout como última línea
    commit_hash = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else None

    _update_task(req.task_id, {
        "phase": "done",
        "commit_hash": commit_hash,
        "approved_by": req.approved_by,
    })

    return ExecuteResponse(
        task_id=req.task_id,
        status="success",
        commit_hash=commit_hash,
        message=f"Remediación aplicada correctamente. Aprobado por: {req.approved_by}",
        executed_at=executed_at,
    )


@router.get(
    "/status/{task_id}",
    response_model=TaskStatus,
    status_code=status.HTTP_200_OK,
    summary="Consulta el estado de una tarea de remediación",
)
async def get_status(task_id: str) -> TaskStatus:
    """
    Devuelve la fase actual de la tarea: planned → executing → done | failed.
    Incluye el commit hash si fue completada, o el mensaje de error si falló.
    """
    task = _task_store.get(task_id)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"task_id '{task_id}' no encontrado.",
        )

    return TaskStatus(
        task_id=task_id,
        phase=task["phase"],
        safe=task.get("safe"),
        risk_level=task.get("risk_level"),
        commit_hash=task.get("commit_hash"),
        error=task.get("error"),
        created_at=task["created_at"],
        updated_at=task["updated_at"],
    )

@router.get("/health")
async def health_check():
    try:
        # L�gica de salud minimalista
        return {"status": "ok", "timestamp": _now()}
    except Exception:
        raise HTTPException(status_code=500, detail="Error interno del servidor (RON3IA_Shield active)")

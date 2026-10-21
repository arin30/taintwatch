"""FastAPI application: browse scenarios, run them under defenses, inspect stored traces."""

from __future__ import annotations

import hmac
import os
from collections import Counter
from typing import Annotated, Any

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from taintwatch import __version__
from taintwatch.baselines import DEFAULT_SPECS, build_defense
from taintwatch.bench import Scenario, Suite, build_suite
from taintwatch.server.results import load_results
from taintwatch.server.service import record_run
from taintwatch.server.store import TraceStore

Limit = Annotated[int, Query(ge=1, le=500)]
Offset = Annotated[int, Query(ge=0)]
DEV_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]


class RunRequest(BaseModel):
    scenario_id: str
    defense: str = "taintwatch"
    seed: int = 7
    confirm: bool = False


class CanonicalizeRequest(BaseModel):
    text: str


class TokenIssueRequest(BaseModel):
    sender: str = "agent-1"
    content: str
    integrity: str = "untrusted"
    confidentiality: str = "public"
    secret_key: str = "taintwatch-demo-key-32-bytes-long!"
    ttl_seconds: float = 300.0


class TokenVerifyRequest(BaseModel):
    content: str
    token: str
    secret_key: str = "taintwatch-demo-key-32-bytes-long!"


class DeclassifyTestRequest(BaseModel):
    pattern: str
    value: str


def _scenario_summary(scenario: Scenario) -> dict[str, Any]:
    return {
        "id": scenario.id,
        "family": scenario.family,
        "task": scenario.task,
        "is_attack": scenario.is_attack,
        "meta": dict(scenario.meta),
    }


def _scenario_detail(scenario: Scenario) -> dict[str, Any]:
    detail = _scenario_summary(scenario)
    detail.update(
        {
            "plan": [{"tool": p.tool, "args": dict(p.args)} for p in scenario.plan],
            "answer": scenario.answer,
            "web": [{"url": url, "text": text} for url, text in scenario.web],
            "inbox": list(scenario.inbox),
            "files": [
                {
                    "path": path,
                    "content": entry.content,
                    "integrity": entry.integrity.name,
                    "confidentiality": entry.confidentiality.name,
                }
                for path, entry in scenario.files
            ],
            "attack": None if scenario.attack is None else scenario.attack.to_dict(),
            "utility": None if scenario.utility is None else scenario.utility.to_dict(),
        }
    )
    return detail


def create_app(
    db_path: str = "taintwatch.db",
    suite: Suite | None = None,
    results_dir: str = "results",
) -> FastAPI:
    """Build the API. ``db_path=":memory:"`` keeps everything in memory (tests)."""
    app = FastAPI(title="Taintwatch", version=__version__)
    app.add_middleware(
        CORSMiddleware, allow_origins=DEV_ORIGINS, allow_methods=["*"], allow_headers=["*"]
    )

    @app.middleware("http")
    async def require_api_key(request: Request, call_next: Any) -> Response:
        configured_key = os.getenv("TAINTWATCH_API_KEY")
        if configured_key:
            supplied_key = request.headers.get("X-API-Key", "")
            if not hmac.compare_digest(supplied_key, configured_key):
                return JSONResponse(
                    status_code=401,
                    content={"detail": "invalid or missing API key"},
                )
        return await call_next(request)

    store = TraceStore(db_path)
    active = suite if suite is not None else build_suite()
    scenarios = active.scenarios
    by_id = {s.id: s for s in scenarios}
    app.state.store = store

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "scenarios": len(scenarios), "runs": store.count_runs()}

    @app.get("/api/defenses")
    def defenses() -> list[dict[str, str]]:
        built = [(spec, build_defense(spec)) for spec in DEFAULT_SPECS]
        return [{"spec": s, "name": d.name, "description": d.description} for s, d in built]

    @app.get("/api/scenarios")
    def list_scenarios(
        limit: Limit = 100,
        offset: Offset = 0,
        family: str | None = None,
        attack: bool | None = None,
    ) -> dict[str, Any]:
        chosen = [
            s
            for s in scenarios
            if (family is None or s.family == family)
            and (attack is None or s.is_attack == attack)
        ]
        page = chosen[offset : offset + limit]
        return {"total": len(chosen), "items": [_scenario_summary(s) for s in page]}

    @app.get("/api/scenarios/{scenario_id}")
    def get_scenario(scenario_id: str) -> dict[str, Any]:
        scenario = by_id.get(scenario_id)
        if scenario is None:
            raise HTTPException(status_code=404, detail=f"unknown scenario {scenario_id!r}")
        return _scenario_detail(scenario)

    @app.post("/api/runs", status_code=201)
    def create_run(request: RunRequest) -> dict[str, Any]:
        scenario = by_id.get(request.scenario_id)
        if scenario is None:
            raise HTTPException(
                status_code=404, detail=f"unknown scenario {request.scenario_id!r}"
            )
        try:
            run_id = record_run(
                store, scenario, request.defense, seed=request.seed, confirm=request.confirm
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        run = store.get_run(run_id)
        if run is None:
            raise HTTPException(status_code=500, detail="stored run could not be read back")
        return run

    @app.get("/api/runs")
    def list_runs(
        limit: Limit = 50,
        offset: Offset = 0,
        defense: str | None = None,
        scenario_id: str | None = None,
    ) -> dict[str, Any]:
        items = store.list_runs(
            defense=defense, scenario_id=scenario_id, limit=limit, offset=offset
        )
        total = store.count_runs(defense=defense, scenario_id=scenario_id)
        return {"total": total, "items": items}

    @app.get("/api/runs/{run_id}")
    def get_run(run_id: int) -> dict[str, Any]:
        run = store.get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail=f"unknown run {run_id}")
        return run

    @app.delete("/api/runs/{run_id}", status_code=204)
    def delete_run(run_id: int) -> Response:
        if not store.delete_run(run_id):
            raise HTTPException(status_code=404, detail=f"unknown run {run_id}")
        return Response(status_code=204)

    @app.get("/api/families")
    def families() -> list[dict[str, Any]]:
        counts = Counter((s.family, s.is_attack) for s in scenarios)
        return [
            {"family": family, "is_attack": is_attack, "count": count}
            for (family, is_attack), count in sorted(counts.items())
        ]

    @app.get("/api/results")
    def results() -> dict[str, Any]:
        data = load_results(results_dir)
        if data is None:
            raise HTTPException(
                status_code=404,
                detail="no results found; run python -m taintwatch.evaluation first",
            )
        return data

    @app.get("/api/stats")
    def stats() -> list[dict[str, Any]]:
        rows = store.stats()
        for row in rows:
            row["attack_success_rate"] = (
                row["attack_successes"] / row["attacks"] if row["attacks"] else None
            )
            row["benign_utility_rate"] = (
                row["benign_ok"] / row["benign"] if row["benign"] else None
            )
        return rows

    @app.post("/api/canonicalize")
    def api_canonicalize(req: CanonicalizeRequest) -> dict[str, Any]:
        from taintwatch.spans.canonical import detect_evasion
        from taintwatch.spans.tstr import TStr

        tstr = TStr.of(req.text)
        report = detect_evasion(tstr)
        return {
            "text": req.text,
            "canonical": report.canonical.text,
            "has_evasion": report.has_evasion,
            "score": round(report.score, 3),
            "techniques": list(report.techniques),
        }

    @app.post("/api/tokens/issue")
    def api_issue_token(req: TokenIssueRequest) -> dict[str, Any]:
        from taintwatch.crypto import TaintTokenSigner
        from taintwatch.labels import Confidentiality, Integrity, Label

        try:
            integ = Integrity[req.integrity.upper()]
            conf = Confidentiality[req.confidentiality.upper()]
        except KeyError as exc:
            raise HTTPException(status_code=400, detail=f"invalid label level: {exc}") from exc

        signer = TaintTokenSigner(req.secret_key.encode("utf-8"), agent_id=req.sender)
        label = Label(integ, conf, frozenset({f"agent:{req.sender}"}))
        token = signer.issue(content=req.content, label=label, ttl_seconds=req.ttl_seconds)
        return {
            "token": token.to_compact(),
            "token_id": token.token_id,
            "content_digest": token.content_digest,
            "merkle_root": token.merkle_root,
            "created_at": token.created_at,
            "expires_at": token.expires_at,
        }

    @app.post("/api/tokens/verify")
    def api_verify_token(req: TokenVerifyRequest) -> dict[str, Any]:
        from taintwatch.crypto import CryptoTaintError, TaintToken, TaintTokenVerifier

        try:
            token = TaintToken.from_compact(req.token)
            verifier = TaintTokenVerifier(req.secret_key.encode("utf-8"))
            result = verifier.verify(token, req.content)
            return {
                "valid": result.valid,
                "label": {
                    "integrity": result.label.integrity.name,
                    "confidentiality": result.label.confidentiality.name,
                    "sources": sorted(result.label.sources),
                },
                "token_id": token.token_id,
                "sender": token.sender,
            }
        except CryptoTaintError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/declassify/test")
    def api_test_declassify(req: DeclassifyTestRequest) -> dict[str, Any]:
        import re

        try:
            matches = bool(re.fullmatch(req.pattern, req.value))
            return {"matches": matches, "pattern": req.pattern, "value": req.value}
        except re.error as exc:
            raise HTTPException(status_code=400, detail=f"invalid regex pattern: {exc}") from exc

    return app

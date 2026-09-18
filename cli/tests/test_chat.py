"""aegis chat against a recorded Gateway stream -- no network."""

from __future__ import annotations

import json

import httpx
from rich.console import Console

from aegis_cli import chat as C
from aegis_cli.config import CLIConfig


def _sse(*frames: tuple[str | None, object]) -> bytes:
    out = []
    for event, data in frames:
        if event:
            out.append(f"event: {event}")
        out.append("data: " + (data if isinstance(data, str) else json.dumps(data)))
        out.append("")
    return ("\n".join(out) + "\n").encode()


SCAN = {"action": "sanitize", "error_code": None,
        "stages": [{"name": "pii_scanner", "status": "flagged", "duration_ms": 12.3, "detail": "1 finding(s)"},
                   {"name": "policy_engine", "status": "pass", "duration_ms": 0.4}],
        "detections": [{"category": "PII_EMAIL", "placeholder": "[EMAIL_1]", "secret": False}],
        "sanitized_messages": [{"role": "user", "content": "Mail [EMAIL_1] now"}], "had_secrets": False}


def _chunk(text: str) -> dict:
    return {"id": "c1", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"content": text}}]}


def _recorded(status: int = 200, body: bytes | None = None, ctype: str = "text/event-stream", capture: dict | None = None):
    def handler(req: httpx.Request) -> httpx.Response:
        if capture is not None:
            capture["headers"] = dict(req.headers)
            capture["json"] = json.loads(req.content)
        return httpx.Response(status, content=body or b"", headers={"content-type": ctype})
    return httpx.Client(transport=httpx.MockTransport(handler), base_url="http://gw")


def test_sse_parser_handles_multiline_and_comments():
    lines = iter(["event: a", "data: 1", "data: 2", "", ": keepalive", "data: {\"x\":1}", ""])
    evs = list(C.iter_sse(lines))
    assert [(e.event, e.data) for e in evs] == [("a", "1\n2"), ("message", '{"x":1}')]


def test_sanitize_stream_rehydrates_from_grounding_frame(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path))
    body = _sse(
        ("aegis.scan", SCAN),
        (None, _chunk("Sure, ")), (None, _chunk("[EMAIL_1].")),
        ("aegis.grounding", {"request_id": "req_1", "grounding": {"status": "pass", "score": 1}, "rehydrated": True,
                             "blocked": False, "final_text": "Sure, a@b.co."}),
        ("aegis.telemetry", {"request_id": "req_1", "provider_used": "groq", "failover_used": False, "cache_hit": False}),
        (None, "[DONE]"),
    )
    cap: dict = {}
    tokens: list[str] = []
    scans: list[dict] = []
    out = C.chat("Mail a@b.co now", cfg=CLIConfig(), client=_recorded(body=body, capture=cap),
                 mode="strict", no_cache=True, reference_docs=["doc one"],
                 on_token=tokens.append, on_scan=scans.append)
    assert out.action == "sanitize" and out.request_id == "req_1" and out.exit_code == 0
    assert "".join(tokens) == out.streamed == "Sure, [EMAIL_1]."
    assert out.answer == "Sure, a@b.co."          # the trailing frame wins
    assert scans and scans[0]["action"] == "sanitize"
    assert out.telemetry["provider_used"] == "groq"
    h = cap["headers"]
    assert h["x-aegis-mode"] == "strict" and h["x-aegis-no-cache"] == "true"
    assert json.loads(h["x-aegis-reference-docs"]) == ["doc one"]
    assert h["x-session-id"].startswith("sess_cli_")
    assert cap["json"]["stream"] is True and cap["json"]["messages"][-1]["content"] == "Mail a@b.co now"


def test_grounding_block_replaces_answer_with_gateway_fallback():
    body = _sse(
        ("aegis.scan", {**SCAN, "action": "allow", "sanitized_messages": None, "detections": []}),
        (None, _chunk("It was 2019.")),
        ("aegis.grounding", {"request_id": "req_2", "grounding": {"status": "block", "score": 0.0},
                             "rehydrated": False, "blocked": True, "final_text": "I cannot verify this."}),
        ("aegis.telemetry", {"request_id": "req_2", "provider_used": "groq", "cache_hit": False}),
        (None, "[DONE]"),
    )
    out = C.chat("when?", cfg=CLIConfig(), client=_recorded(body=body))
    assert out.streamed == "It was 2019." and out.answer == "I cannot verify this."
    assert out.exit_code == 0  # a grounding block is not a policy block


def test_policy_block_is_a_json_error_not_a_stream():
    err = json.dumps({"error": {"code": "CREDENTIAL_LEAK_PREVENTED", "message": "blocked", "request_id": "req_3"}}).encode()
    out = C.chat("key", cfg=CLIConfig(), client=_recorded(status=400, body=err, ctype="application/json"))
    assert out.blocked and out.error_code == "CREDENTIAL_LEAK_PREVENTED" and out.request_id == "req_3"
    assert out.exit_code == 1


def test_provider_failure_is_exit_2():
    err = json.dumps({"error": {"code": "AEGIS_PROVIDER_UNAVAILABLE", "message": "all failed", "request_id": "req_4"}}).encode()
    out = C.chat("hi", cfg=CLIConfig(), client=_recorded(status=502, body=err, ctype="application/json"))
    assert not out.blocked and out.exit_code == 2 and "all failed" in out.error_message


def test_gateway_unreachable_is_exit_2():
    def boom(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=req)
    client = httpx.Client(transport=httpx.MockTransport(boom), base_url="http://gw")
    out = C.chat("hi", cfg=CLIConfig(gateway_url="http://gw"), client=client)
    assert out.exit_code == 2 and "unreachable" in out.error_message


def test_renderers_do_not_crash_and_never_show_values():
    console = Console(record=True, width=100, force_terminal=False)
    C.render_stages(SCAN["stages"], console)
    C.render_sanitized(SCAN, console)
    out = C.ChatOutcome(request_id="req_5", error_code="CREDENTIAL_LEAK_PREVENTED", blocked=True,
                        error_message="blocked", scan={"detections": [{"category": "SECRET_AWS_ACCESS_KEY"}]})
    C.render_block(out, console)
    C.render_footer(C.ChatOutcome(telemetry={"provider_used": "groq", "cache_hit": True, "failover_used": True},
                                  grounding={"grounding": {"status": "pass", "score": 1}, "rehydrated": True}), console)
    C.render_audit({"policy_action": "SANITIZE", "rules_fired": ["pii"], "estimated_cost_usd": 0.000001}, console)
    text = console.export_text()
    assert "pii_scanner" in text and "[EMAIL_1]" in text and "aegis appeal req_5" in text
    assert "HIT" in text and "failover" in text and "estimate" in text


def test_create_appeal_posts_the_contract():
    cap: dict = {}

    def handler(req: httpx.Request) -> httpx.Response:
        cap["json"] = json.loads(req.content); cap["path"] = req.url.path
        return httpx.Response(201, json={"review": {"id": "rev_1", "status": "PENDING"}, "accepted": True})
    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://engine")
    status, body = C.create_appeal("req_9", "false positive", cfg=CLIConfig(), client=client)
    assert status == 201 and body["review"]["id"] == "rev_1"
    assert cap["path"] == "/api/reviews" and cap["json"]["original_decision"] == "BLOCK"
    assert cap["json"]["user_justification"] == "false positive"

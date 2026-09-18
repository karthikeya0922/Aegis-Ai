"""`aegis` -- Aegis from the terminal.

Exit codes are the contract for CI and hooks:
  0  clean (or only findings below --fail-on)
  1  findings at or above --fail-on
  2  error (bad arguments, backend not found, git failure, service unreachable)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.markup import escape
from rich.table import Table

from aegis_cli import __version__
from aegis_cli.config import CLIConfig

app = typer.Typer(add_completion=False, no_args_is_help=True, rich_markup_mode="rich",
                  help="Aegis from the terminal: pre-commit secret/PII scanning and guarded chat through the Gateway.")
console = Console()
err = Console(stderr=True)

DISCLAIMER = "heuristic detection -- pattern, entropy and (with --pii) NER based; it can miss and it can over-flag fixtures"


def _version_cb(value: bool) -> None:
    if value:
        console.print(f"aegis-cli {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(False, "--version", "-V", callback=_version_cb, is_eager=True, help="Print version and exit."),
) -> None:
    pass


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------


@app.command()
def config(as_json: bool = typer.Option(False, "--json", help="Machine-readable output.")) -> None:
    """Show the resolved configuration and where each value came from."""
    cfg = CLIConfig.load()
    if as_json:
        console.print_json(json.dumps({k: v for k, v, _ in cfg.as_rows()}))
        return
    t = Table(title="aegis config", show_lines=False)
    t.add_column("key"); t.add_column("value"); t.add_column("source", style="dim")
    for k, v, s in cfg.as_rows():
        t.add_row(k, v, s)
    console.print(t)
    from aegis_cli.config import CONFIG_FILE
    console.print(f"[dim]config file: {CONFIG_FILE}  (env vars override it)[/dim]")


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

_ACTION_STYLE = {"block": "bold red", "sanitize": "yellow", "warn": "cyan", "allow": "dim"}


@app.command()
def scan(
    paths: list[Path] = typer.Argument(None, help="Files or directories. Default: current directory."),
    staged: bool = typer.Option(False, "--staged", help="Scan the git index (what is about to be committed)."),
    diff: Optional[str] = typer.Option(None, "--diff", metavar="REF", help="Only lines added since REF (e.g. origin/main)."),
    profile: Optional[str] = typer.Option(None, "--profile", help="Policy profile: default | strict | permissive."),
    pii: bool = typer.Option(False, "--pii", help="Also run the PII scanner (loads the NER model; slower)."),
    fail_on: str = typer.Option("secret", "--fail-on", help="Exit 1 on: secret | pii | any."),
    baseline: Optional[Path] = typer.Option(None, "--baseline", help="Suppress fingerprints listed in this file."),
    update_baseline: bool = typer.Option(False, "--update-baseline", help="Write current findings to --baseline and exit 0."),
    fmt: str = typer.Option("table", "--format", help="table | json | sarif"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write --format json/sarif here instead of stdout."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only the summary line and failing findings."),
    hook: bool = typer.Option(False, "--hook", hidden=True, help="Pre-commit presentation."),
    include: list[str] = typer.Option([], "--include", help="Glob to include (repeatable)."),
    exclude: list[str] = typer.Option([], "--exclude", help="Glob to exclude (repeatable)."),
) -> None:
    """Scan files, the git index, or a diff for credentials (and PII with --pii).

    Matched values are never printed; a masked preview is shown at most.
    """
    from aegis_cli import scan as S
    from aegis_cli.local import BackendNotFound

    cfg = CLIConfig.load()
    profile = profile or cfg.profile
    if fail_on not in S.FAIL_ON_RANK:
        err.print(f"[red]--fail-on must be one of {', '.join(S.FAIL_ON_RANK)}[/red]"); raise typer.Exit(2)
    if fmt not in {"table", "json", "sarif"}:
        err.print("[red]--format must be table, json or sarif[/red]"); raise typer.Exit(2)

    try:
        only_lines = None
        if staged:
            sources = S.staged_files()
            what = "staged"
        elif diff:
            only_lines = S.diff_added_lines(diff)
            root = S._git_root(Path.cwd()) or Path.cwd()
            sources = [(p, (root / p).read_text(encoding="utf-8", errors="replace")) for p in only_lines if (root / p).is_file()]
            what = f"added since {diff}"
        else:
            sources = S.iter_files(paths or [Path.cwd()], include=include or None, exclude=exclude or None)
            what = ", ".join(str(p) for p in (paths or [Path(".")]))
        base = S.load_baseline(baseline) if baseline and not update_baseline else None
        res = S.run_scan(sources, profile=profile, pii=pii, fail_on=fail_on, baseline=base, only_lines=only_lines)
    except BackendNotFound as exc:
        err.print(f"[red]{exc}[/red]"); raise typer.Exit(2)
    except RuntimeError as exc:
        err.print(f"[red]{exc}[/red]"); raise typer.Exit(2)

    if update_baseline:
        if not baseline:
            err.print("[red]--update-baseline needs --baseline PATH[/red]"); raise typer.Exit(2)
        S.write_baseline(baseline, res.findings)
        console.print(f"baseline written: {baseline} ({len(res.findings)} fingerprint(s), no values stored)")
        raise typer.Exit(0)

    if fmt == "json":
        body = json.dumps(res.to_json(), indent=2)
        _emit(body, output)
        raise typer.Exit(res.exit_code)
    if fmt == "sarif":
        body = json.dumps(S.to_sarif(res, __version__), indent=2)
        _emit(body, output)
        raise typer.Exit(res.exit_code)

    failing_ids = {id(f) for f in res.failing}
    shown = [f for f in res.findings if not quiet or id(f) in failing_ids]
    if shown:
        t = Table(show_lines=False, title=None, pad_edge=False)
        t.add_column("location", overflow="fold")
        t.add_column("type", no_wrap=True)
        t.add_column("category", style="dim")
        t.add_column("conf", justify="right")
        t.add_column("policy")
        t.add_column("preview", no_wrap=True)
        t.add_column("note", style="dim")
        for f in shown:
            style = _ACTION_STYLE.get(f.action, "")
            note = "allowed by annotation" if f.allowed_inline else ("" if id(f) in failing_ids else "not failing")
            t.add_row(f"{f.path}:{f.line}:{f.column}", f.type, f.category, f"{f.confidence:.2f}",
                      f"[{style}]{f.action.upper()}[/{style}]" if style else f.action.upper(), f.preview, note)
        console.print(t)

    n_fail = len(res.failing)
    summary = (f"scanned {res.files_scanned} file(s) ({escape(what)}) -- {len(res.findings)} finding(s), "
               f"{n_fail} failing (--fail-on {fail_on}, profile {profile})")
    if res.suppressed_baseline or res.suppressed_inline:
        summary += f"; suppressed: {res.suppressed_baseline} baseline, {res.suppressed_inline} annotated"
    console.print(("[red]" if n_fail else "[green]") + summary + ("[/red]" if n_fail else "[/green]"))
    console.print(f"[dim]{DISCLAIMER}[/dim]")
    if hook and n_fail:
        console.print()
        console.print("[bold]Commit refused.[/bold] Remove the credential and re-stage, or:")
        console.print("  one-off:   AEGIS_ALLOW=1 git commit ...")
        console.print("  per line:  append  # aegis:allow  to that line (recorded in every scan)")
    raise typer.Exit(res.exit_code)


def _emit(body: str, output: Path | None) -> None:
    if output:
        output.write_text(body + "\n", encoding="utf-8")
        console.print(f"written: {output}")
    else:
        sys.stdout.write(body + "\n")


# ---------------------------------------------------------------------------
# hooks
# ---------------------------------------------------------------------------


@app.command("install-hook")
def install_hook(
    force: bool = typer.Option(False, "--force", help="Replace an existing non-aegis pre-commit hook."),
    uninstall: bool = typer.Option(False, "--uninstall", help="Remove the aegis hook."),
) -> None:
    """Install a git pre-commit hook that runs `aegis scan --staged`."""
    from aegis_cli import hook as H

    try:
        if uninstall:
            console.print("removed" if H.uninstall() else "no aegis hook installed")
            raise typer.Exit(0)
        path, status = H.install(force=force)
    except (RuntimeError, FileExistsError) as exc:
        err.print(f"[red]{exc}[/red]"); raise typer.Exit(2)
    console.print(f"pre-commit hook {status}: {path}")
    if (Path.cwd() / ".pre-commit-config.yaml").exists():
        console.print("\n[dim]This repo uses the pre-commit framework; to run through it instead, add:[/dim]")
        console.print(H.PRE_COMMIT_FRAMEWORK_SNIPPET)
    console.print("[dim]Override once with AEGIS_ALLOW=1, or per line with  # aegis:allow[/dim]")


# ---------------------------------------------------------------------------
# chat / appeal / reviews  (through the Gateway and the Inspector)
# ---------------------------------------------------------------------------


@app.command()
def chat(
    prompt: Optional[str] = typer.Argument(None, help="One prompt. Omit for a REPL."),
    mode: str = typer.Option("sanitize", "--mode", help="sanitize | strict (x-aegis-mode)."),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass the semantic cache for this request."),
    confidential: bool = typer.Option(False, "--confidential", help="Confidential mode: strict profile, no cache."),
    ref: list[Path] = typer.Option([], "--ref", help="Reference document(s) for grounding (repeatable)."),
    explain: bool = typer.Option(False, "--explain", help="After the answer, print the Inspector's audit row."),
    as_json: bool = typer.Option(False, "--json", help="Machine-readable outcome instead of the readout."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Answer only; no pipeline readout."),
) -> None:
    """Chat through the Aegis Gateway and watch the pipeline decide.

    Routing, failover, cache and audit all happen for real in the Gateway;
    this renders the aegis.* events it streams back.
    """
    from aegis_cli import chat as C

    cfg = CLIConfig.load()
    if mode not in {"sanitize", "strict"}:
        err.print("[red]--mode must be sanitize or strict[/red]"); raise typer.Exit(2)
    docs = []
    for r in ref:
        try:
            docs.append(r.read_text(encoding="utf-8"))
        except OSError as exc:
            err.print(f"[red]cannot read {r}: {exc}[/red]"); raise typer.Exit(2)

    def one(text: str, history: list[dict[str, str]]) -> C.ChatOutcome:
        started = {"any": False}

        def on_token(tok: str) -> None:
            if not started["any"]:
                if not quiet:
                    console.print("[bold]answer[/bold]")
                started["any"] = True
            sys.stdout.write(tok); sys.stdout.flush()

        def on_scan(scan: dict) -> None:
            if quiet or as_json:
                return
            C.render_stages(scan.get("stages", []), console)
            if scan.get("action") == "sanitize":
                C.render_sanitized(scan, console)
            elif scan.get("action") == "warn":
                console.print("[yellow]warning recorded; original prompt forwarded[/yellow]")

        out = C.chat(text, cfg=cfg, mode=mode, no_cache=no_cache or confidential, confidential=confidential,
                     reference_docs=docs or None, history=history,
                     on_token=None if as_json else on_token, on_scan=on_scan)
        if started["any"]:
            sys.stdout.write("\n"); sys.stdout.flush()
        if as_json:
            console.print_json(json.dumps({
                "request_id": out.request_id, "action": out.action, "error_code": out.error_code,
                "blocked": out.blocked, "answer": out.answer, "grounding": out.grounding,
                "telemetry": out.telemetry, "error": out.error_message, "exit_code": out.exit_code,
            }))
            return out
        if out.blocked:
            C.render_block(out, console)
            return out
        if out.error_message and not out.answer:
            err.print(f"[red]{out.error_message}[/red]")
            return out
        if out.answer != out.streamed:
            g = out.grounding or {}
            title = "final answer (grounding fallback)" if g.get("blocked") else "final answer (rehydrated)"
            console.print(Panel(out.answer, title=title, title_align="left",
                                border_style="red" if g.get("blocked") else "green"))
        if not quiet:
            C.render_footer(out, console)
            if explain and out.request_id:
                audit = C.fetch_audit(out.request_id, cfg=cfg)
                if audit:
                    C.render_audit(audit, console)
                else:
                    console.print(f"[dim]no audit row yet for {out.request_id}[/dim]")
        return out

    if prompt is not None:
        out = one(prompt, [])
        raise typer.Exit(out.exit_code)

    console.print(f"[dim]aegis chat -- gateway {cfg.gateway_url}, mode {mode}. Ctrl-D or /quit to leave.[/dim]")
    history: list[dict[str, str]] = []
    while True:
        try:
            text = console.input("[bold cyan]> [/bold cyan]").strip()
        except (EOFError, KeyboardInterrupt):
            console.print(); break
        if not text:
            continue
        if text in {"/quit", "/exit"}:
            break
        out = one(text, history)
        if out.answer and not out.blocked:
            history += [{"role": "user", "content": text}, {"role": "assistant", "content": out.answer}]
    raise typer.Exit(0)


@app.command()
def appeal(
    request_id: str = typer.Argument(..., help="The request id from a blocked chat."),
    justification: str = typer.Argument(..., help="Why this should be allowed (1-2000 chars)."),
    decision: str = typer.Option("BLOCK", "--decision", help="Original decision being appealed."),
) -> None:
    """Ask a human reviewer to reconsider a blocked request (Requirement 1: human oversight)."""
    from aegis_cli import chat as C

    cfg = CLIConfig.load()
    try:
        status, body = C.create_appeal(request_id, justification, cfg=cfg, decision=decision.upper())
    except Exception as exc:  # noqa: BLE001
        err.print(f"[red]inspector unreachable at {cfg.engine_url}: {exc.__class__.__name__}[/red]"); raise typer.Exit(2)
    if status == 201 and body.get("accepted", True):
        rec = body.get("review", {})
        console.print(f"appeal opened: [bold]{rec.get('id')}[/bold] (status {rec.get('status')})")
        console.print("[dim]a reviewer decides with:  aegis reviews decide <id> --approve|--deny[/dim]")
        raise typer.Exit(0)
    err.print(f"[red]appeal not accepted ({status}): {body.get('reason') or body.get('detail') or body}[/red]")
    raise typer.Exit(1)


reviews_app = typer.Typer(help="The human-review queue.", no_args_is_help=True)
app.add_typer(reviews_app, name="reviews")


@reviews_app.command("list")
def reviews_list(status: Optional[str] = typer.Option("PENDING", "--status", help="PENDING | APPROVED | DENIED | all")) -> None:
    """List review requests."""
    import httpx

    cfg = CLIConfig.load()
    params = {} if status in (None, "all") else {"status": status.upper()}
    try:
        r = httpx.get(f"{cfg.engine_url}/api/reviews", params=params, timeout=10)
    except httpx.HTTPError as exc:
        err.print(f"[red]inspector unreachable: {exc.__class__.__name__}[/red]"); raise typer.Exit(2)
    items = r.json().get("items", [])
    t = Table(title=f"reviews ({status or 'all'})", title_justify="left")
    for col in ("id", "request_id", "decision", "rule", "status"):
        t.add_column(col, no_wrap=True)
    t.add_column("justification", overflow="fold")
    for it in items:
        t.add_row(it.get("id", ""), it.get("request_id", ""), str(it.get("original_decision", "")),
                  it.get("rule_fired") or "-", str(it.get("status", "")), (it.get("user_justification") or "")[:60])
    console.print(t)


@reviews_app.command("decide")
def reviews_decide(
    review_id: str = typer.Argument(...),
    approve: bool = typer.Option(False, "--approve"),
    deny: bool = typer.Option(False, "--deny"),
    note: Optional[str] = typer.Option(None, "--note"),
    reviewer: Optional[str] = typer.Option(None, "--reviewer", help="Your reviewer reference (hashed on store)."),
) -> None:
    """Approve or deny an appeal. Needs AEGIS_REVIEWER_TOKEN when the Inspector has one set."""
    import httpx

    if approve == deny:
        err.print("[red]pass exactly one of --approve / --deny[/red]"); raise typer.Exit(2)
    cfg = CLIConfig.load()
    headers = {"X-Reviewer-Token": cfg.reviewer_token} if cfg.reviewer_token else {}
    try:
        r = httpx.post(f"{cfg.engine_url}/api/reviews/{review_id}/decision", headers=headers, timeout=10,
                       json={"approve": approve, "reviewer_ref": reviewer, "reviewer_note": note})
    except httpx.HTTPError as exc:
        err.print(f"[red]inspector unreachable: {exc.__class__.__name__}[/red]"); raise typer.Exit(2)
    if r.status_code == 401:
        err.print("[red]reviewer token required: set AEGIS_REVIEWER_TOKEN[/red]"); raise typer.Exit(2)
    if r.status_code != 200:
        err.print(f"[red]{r.status_code}: {r.text[:300]}[/red]"); raise typer.Exit(1)
    body = r.json()
    rec = body.get("review", {})
    console.print(f"review {rec.get('id')} -> [bold]{rec.get('status')}[/bold]")
    if body.get("override_token"):
        console.print("override token (single-use, request-scoped, expires):")
        console.print(f"  [bold]{body['override_token']}[/bold]")
        console.print("[dim]resend the original request with override_token to /inspect, or via the Gateway[/dim]")


@app.command()
def status(
    hours: int = typer.Option(24, "--hours", help="Metrics window."),
    watch: bool = typer.Option(False, "--watch", help="Redraw every 5 seconds."),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """One screen: services, traffic, security, cache/sustainability estimates, providers, reviews, fairness."""
    import time

    from aegis_cli import status as St

    cfg = CLIConfig.load()
    while True:
        snap = St.collect(cfg, hours=hours)
        if as_json:
            console.print_json(json.dumps(snap.to_json(), default=str))
        else:
            if watch:
                console.clear()
            St.render(snap, cfg, console)
        if not watch:
            raise typer.Exit(0 if snap.health else 2)
        try:
            time.sleep(5)
        except KeyboardInterrupt:
            raise typer.Exit(0)


def main() -> None:
    app()


if __name__ == "__main__":
    main()

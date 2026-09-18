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


def main() -> None:
    app()


if __name__ == "__main__":
    main()

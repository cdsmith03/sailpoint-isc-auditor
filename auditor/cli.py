"""
CLI entry point for sailpoint-isc-auditor.

Usage:
  isc-audit run --all
  isc-audit run --families MI LI AR
  isc-audit run --detectors MI-01 MI-02 LI-01
  isc-audit run --all --output html --out report.html
  isc-audit suppress MI-06 --object-id svc-legacy-erp --reason "JIRA-4521" --expires 2025-09-01
  isc-audit suppressions list
  isc-audit history
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime
from pathlib import Path

import click
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from . import __version__
from .config import AuditorConfig, PolicyPack
from .models import HealthBand, Severity

logger = logging.getLogger(__name__)

console = Console()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BAND_COLORS = {
    HealthBand.HEALTHY:        "bold green",
    HealthBand.STABLE:         "bold cyan",
    HealthBand.EXPOSED:        "bold yellow",
    HealthBand.HIGH_RISK:      "bold red",
    HealthBand.CRITICAL:       "bold red on white",
}

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "red",
    Severity.MEDIUM:   "yellow",
    Severity.LOW:      "dim",
    Severity.INFO:     "dim",
}


def _print_header(tenant_url: str, version: str = __version__) -> None:
    console.print()
    console.print(Panel(
        f"[bold]SailPoint ISC Auditor[/bold] v{version}\n"
        f"[dim]Tenant:[/dim] {tenant_url}",
        style="blue",
        expand=False,
    ))
    console.print()


def _print_health_score(health) -> None:
    band_color = BAND_COLORS.get(health.band, "white")
    score_text = f"[{band_color}]{health.tenant_health:.0f} / 100  ({health.band.value.upper()})[/{band_color}]"

    trend_str = ""
    if health.trend is not None:
        arrow = "↑" if health.trend > 0 else "↓" if health.trend < 0 else "→"
        color = "green" if health.trend > 0 else "red" if health.trend < 0 else "dim"
        trend_str = f"  [{color}]{arrow} {abs(health.trend):.1f} vs last run[/{color}]"

    console.rule()
    console.print(f"  TENANT HEALTH SCORE: {score_text}{trend_str}")
    console.print(f"  [dim]Coverage confidence: {health.coverage_confidence.score_display}/100[/dim]")
    console.rule()
    console.print()

    if health.has_critical_conditions:
        console.print(Panel(
            "\n".join(
                f"[bold red]  ! {cc.title}[/bold red]\n"
                f"    [dim]{cc.description}[/dim]"
                for cc in health.critical_conditions
            ),
            title="[bold red]CRITICAL CONDITIONS PRESENT[/bold red]",
            border_style="red",
        ))
        console.print()


def _print_summary_table(result) -> None:
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    table.add_column("Family", style="bold")
    table.add_column("Score", justify="right")
    table.add_column("Critical", justify="right")
    table.add_column("High", justify="right")
    table.add_column("Medium", justify="right")

    for name, fs in result.health_score.family_scores.items():
        score_color = "green" if fs.score >= 80 else "yellow" if fs.score >= 60 else "red"
        table.add_row(
            fs.family.value,
            f"[{score_color}]{fs.score:.0f}[/{score_color}]",
            f"[red]{fs.critical_count}[/red]"    if fs.critical_count else "[dim]0[/dim]",
            f"[yellow]{fs.high_count}[/yellow]"  if fs.high_count     else "[dim]0[/dim]",
            f"[yellow]{fs.medium_count}[/yellow]" if fs.medium_count  else "[dim]0[/dim]",
        )

    console.print("  Control family breakdown")
    console.print(table)


def _print_top_findings(result, limit: int = 5) -> None:
    active = [f for f in result.findings if not f.suppressed]
    # Sort: critical first, then by risk score desc
    active.sort(key=lambda f: (
        f.severity != Severity.CRITICAL,
        -(f.risk_score.normalized if f.risk_score else 0),
    ))

    if not active:
        console.print("  [green]No active findings.[/green]")
        return

    console.print(f"  [bold]Top findings[/bold] ({len(active)} total)\n")
    for f in active[:limit]:
        sev_color = SEVERITY_COLORS.get(f.severity, "white")
        console.print(
            f"  [{sev_color}]{f.severity.value.upper():8}[/{sev_color}] "
            f"[bold]{f.detector_id}[/bold] {f.title}"
        )
        console.print(
            f"           [dim]{', '.join(f.evidence.affected_object_names[:3])}"
            f"{'...' if len(f.evidence.affected_object_names) > 3 else ''}[/dim]"
        )
    console.print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(__version__, prog_name="isc-audit")
def main() -> None:
    """SailPoint ISC Auditor — AI-powered identity security audit engine."""


@main.command()
@click.option("--all",   "run_all",  is_flag=True,  help="Run all detectors")
@click.option("--families",          multiple=True,  help="Run specific families: MI IH LI AR GQ CR")
@click.option("--detectors",         multiple=True,  help="Run specific detectors: MI-01 LI-05 ...")
@click.option("--output",            default="terminal", type=click.Choice(["terminal", "html", "json"]))
@click.option("--out",               default=None,   help="Output file path")
@click.option("--policy-pack",       default=None,   help="Path to custom policy pack YAML")
@click.option("--no-ai",             is_flag=True,   help="Skip Claude AI analysis (faster)")
@click.option("--verbose", "-v",     is_flag=True,   help="Verbose logging")
def run(
    run_all: bool,
    families: tuple[str, ...],
    detectors: tuple[str, ...],
    output: str,
    out: str | None,
    policy_pack: str | None,
    no_ai: bool,
    verbose: bool,
) -> None:
    """Run an audit against your ISC tenant."""

    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(message)s",
    )

    if not run_all and not families and not detectors:
        console.print("[red]Specify --all, --families, or --detectors[/red]")
        sys.exit(1)

    # Load config — Anthropic key is only required when AI analysis is enabled
    try:
        config = AuditorConfig.from_env(require_ai=not no_ai)
    except OSError as e:
        console.print(f"[red]Configuration error:[/red] {e}")
        sys.exit(1)

    # Load policy pack
    policy = PolicyPack.from_yaml(policy_pack) if policy_pack else PolicyPack.default()

    _print_header(config.tenant_url)

    # Run audit (import here to keep startup fast)
    from .engine import run_audit

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Running audit...", total=None)

        # Use filename only for cleaner report metadata (not full path)
        policy_name = Path(policy_pack).name if policy_pack else "default"

        result = run_audit(
            config=config,
            policy=policy,
            policy_name=policy_name,
            run_all=run_all,
            families=list(families),
            detectors=list(detectors),
            run_ai=not no_ai,
            progress_callback=lambda msg: progress.update(task, description=msg),
        )

    # Output
    _print_health_score(result.health_score)
    _print_summary_table(result)
    _print_top_findings(result)

    if output == "html":
        from .reporters.html_reporter import generate_html_report
        path = out or f"audit_{datetime.now().strftime('%Y-%m-%d_%H-%M')}.html"
        generate_html_report(result, Path(path))
        console.print(f"  [green]HTML report written to: {path}[/green]")

    elif output == "json":
        path = out or f"audit_{datetime.now().strftime('%Y-%m-%d_%H-%M')}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(result.model_dump(mode="json"), f, indent=2, default=str)
        console.print(f"  [green]JSON findings written to: {path}[/green]")

    # Save history for trend tracking
    _save_history(config, result)

    console.print()


@main.command()
@click.argument("detector_id")
@click.option("--object-id",  required=True,  help="ID of the object to suppress")
@click.option("--reason",     required=True,  help="Why this finding is suppressed")
@click.option("--ticket",     default=None,   help="Ticket reference e.g. JIRA-4521")
@click.option("--expires",    default=None,   help="Expiry date YYYY-MM-DD")
def suppress(detector_id: str, object_id: str, reason: str, ticket: str | None, expires: str | None) -> None:
    """Suppress a finding with a reason and optional expiry."""
    from .suppressions import add_suppression
    add_suppression(detector_id, object_id, reason, ticket, expires)
    console.print(f"[green]Suppressed {detector_id} for object {object_id}[/green]")
    if expires:
        console.print(f"[dim]Expires: {expires}[/dim]")


@main.group()
def suppressions() -> None:
    """Manage finding suppressions."""


@suppressions.command(name="list")
def list_suppressions() -> None:
    """List all active suppressions."""
    from .suppressions import list_suppressions as _list
    items = _list()
    if not items:
        console.print("[dim]No active suppressions.[/dim]")
        return

    table = Table(box=box.SIMPLE, header_style="bold")
    table.add_column("Detector")
    table.add_column("Object ID")
    table.add_column("Reason")
    table.add_column("Ticket")
    table.add_column("Expires")

    for s in items:
        table.add_row(
            s["detector_id"],
            s["object_id"],
            s["reason"],
            s.get("ticket") or "—",
            s.get("expires_at") or "never",
        )
    console.print(table)


@main.command()
def history() -> None:
    """Show tenant health score history."""
    from .suppressions import load_history
    records = load_history()
    if not records:
        console.print("[dim]No history yet. Run an audit first.[/dim]")
        return

    table = Table(box=box.SIMPLE, header_style="bold")
    table.add_column("Date")
    table.add_column("Score", justify="right")
    table.add_column("Band")
    table.add_column("Coverage", justify="right")
    table.add_column("Critical", justify="right")

    for r in records[-20:]:  # last 20 runs
        score = r.get("tenant_health", 0)
        color = "green" if score >= 75 else "yellow" if score >= 60 else "red"
        table.add_row(
            r.get("date", "—"),
            f"[{color}]{score:.0f}[/{color}]",
            r.get("band", "—"),
            str(r.get("coverage", "—")),
            str(r.get("critical_count", "—")),
        )
    console.print(table)


def _save_history(config: AuditorConfig, result) -> None:
    """Append this run's score to the history file."""
    try:
        config.history_file.parent.mkdir(parents=True, exist_ok=True)
        records = []
        if config.history_file.exists():
            with open(config.history_file, encoding="utf-8") as f:
                records = json.load(f)

        records.append({
            "date":           datetime.now().strftime("%Y-%m-%d %H:%M"),
            "tenant_url":     config.tenant_url,
            "tenant_health":  result.health_score.tenant_health,
            "posture_score":  result.health_score.posture_score,
            "band":           result.health_score.band.value,
            "coverage":       result.health_score.coverage_confidence.score_display,
            "critical_count": result.critical_count,
            "total_findings": result.total_active,
        })

        with open(config.history_file, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2)
    except (OSError, ValueError, TypeError) as exc:
        logger.debug("History write failed (non-critical): %s", exc)


if __name__ == "__main__":
    main()

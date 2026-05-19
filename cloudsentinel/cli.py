from __future__ import annotations

import json
import logging
import time
from typing import Optional

import click
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cloudsentinel.config import ALL_SERVICES, Config
from cloudsentinel.models import ScanResult, Severity

console = Console()


# ------------------------------------------------------------------ scan engine
def _run_scan(config: Config, enable_ml: bool) -> ScanResult:
    from cloudsentinel.analyzers.ml import AnomalyDetector
    from cloudsentinel.analyzers.rules import RulesEngine
    from cloudsentinel.collectors.cloudfront import CloudFrontCollector
    from cloudsentinel.collectors.dynamodb import DynamoDBCollector
    from cloudsentinel.collectors.ebs import EBSCollector
    from cloudsentinel.collectors.ec2 import EC2Collector
    from cloudsentinel.collectors.elastic_ip import ElasticIPCollector
    from cloudsentinel.collectors.elb import ELBCollector
    from cloudsentinel.collectors.iam import IAMCollector
    from cloudsentinel.collectors.lambda_ import LambdaCollector
    from cloudsentinel.collectors.nat_gateway import NATGatewayCollector
    from cloudsentinel.collectors.rds import RDSCollector
    from cloudsentinel.collectors.s3 import S3Collector

    collector_map = {
        "s3": S3Collector,
        "ec2": EC2Collector,
        "rds": RDSCollector,
        "lambda": LambdaCollector,
        "ebs": EBSCollector,
        "elb": ELBCollector,
        "cloudfront": CloudFrontCollector,
        "nat_gateway": NATGatewayCollector,
        "elastic_ip": ElasticIPCollector,
        "dynamodb": DynamoDBCollector,
        "iam": IAMCollector,
    }
    # Services that are global (region-agnostic)
    global_services = {"s3", "iam", "cloudfront"}

    result = ScanResult()
    rules = RulesEngine(config)
    detector = AnomalyDetector(config) if enable_ml else None

    start = time.time()
    all_resources: dict[str, list[dict]] = {}
    active_services = config.services or ALL_SERVICES

    for svc in active_services:
        cls = collector_map.get(svc)
        if cls is None:
            continue

        collector = cls(config)
        resources: list[dict] = []

        if svc in global_services:
            with console.status(f"[cyan]Collecting {svc.upper()}…"):
                resources = collector.safe_collect(config.active_regions[0])
        else:
            for region in config.active_regions:
                with console.status(f"[cyan]Collecting {svc.upper()} in {region}…"):
                    resources.extend(collector.safe_collect(region))

        all_resources[svc] = resources
        result.scanned_services.append(svc)

        result.findings.extend(rules.analyze(svc, resources))
        if detector:
            result.findings.extend(detector.detect(svc, resources))

    if detector:
        result.findings.extend(detector.detect_cost_anomalies(all_resources))

    result.scanned_regions = list(config.active_regions)
    result.scan_duration_seconds = time.time() - start
    return result


# ------------------------------------------------------------------ display
_SEVERITY_COLOR = {
    "CRITICAL": "red",
    "HIGH": "yellow",
    "MEDIUM": "cyan",
    "LOW": "blue",
    "INFO": "white",
}
_SEVERITY_ORDER = {s: i for i, s in enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])}


def _print_results(result: ScanResult) -> None:
    summary = (
        f"[bold]Findings:[/bold] {len(result.findings)}  "
        f"[red]Critical: {result.critical_count}[/red]  "
        f"[yellow]High: {result.high_count}[/yellow]\n"
        f"[bold]Est. monthly savings:[/bold] [green]${result.total_monthly_savings:,.2f}[/green]\n"
        f"[bold]Services:[/bold] {', '.join(result.scanned_services)}\n"
        f"[bold]Regions:[/bold] {', '.join(result.scanned_regions)}\n"
        f"[bold]Duration:[/bold] {result.scan_duration_seconds:.1f}s"
    )
    console.print(Panel(summary, title="[bold cyan]CloudSentinel[/bold cyan]", expand=False))

    if not result.findings:
        console.print("[green]No issues found — your AWS account looks clean![/green]")
        return

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta")
    table.add_column("Severity", width=10)
    table.add_column("Service", width=12)
    table.add_column("Resource", width=30)
    table.add_column("Region", width=14)
    table.add_column("Finding", width=46)
    table.add_column("Savings/mo", justify="right", width=11)

    for f in sorted(result.findings, key=lambda f: _SEVERITY_ORDER.get(f.severity.value, 99)):
        color = _SEVERITY_COLOR.get(f.severity.value, "white")
        savings = f"${f.estimated_monthly_savings:,.0f}" if f.estimated_monthly_savings > 0 else "-"
        name = f.resource_name
        title = f.title
        table.add_row(
            f"[{color}]{f.severity.value}[/{color}]",
            f.service,
            (name[:28] + "..") if len(name) > 30 else name,
            f.region,
            (title[:44] + "..") if len(title) > 46 else title,
            f"[green]{savings}[/green]" if f.estimated_monthly_savings > 0 else savings,
        )

    console.print(table)


# ------------------------------------------------------------------ output helpers
def _save_json(result: ScanResult, path: str) -> None:
    data = {
        "summary": {
            "total_findings": len(result.findings),
            "critical_count": result.critical_count,
            "high_count": result.high_count,
            "total_monthly_savings_usd": round(result.total_monthly_savings, 2),
            "scan_duration_seconds": round(result.scan_duration_seconds, 1),
            "scanned_services": result.scanned_services,
            "scanned_regions": result.scanned_regions,
        },
        "findings": [f.to_dict() for f in result.findings],
        "errors": result.errors,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CloudSentinel Report</title>
<style>
body{font-family:Arial,sans-serif;margin:24px;background:#f5f5f5}
h1{color:#232f3e}
.summary{background:#fff;padding:20px;border-radius:8px;margin-bottom:20px;box-shadow:0 2px 4px rgba(0,0,0,.1)}
.savings{font-size:2em;color:#2ea44f;font-weight:bold}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 4px rgba(0,0,0,.1)}
th{background:#232f3e;color:#fff;padding:12px;text-align:left}
td{padding:10px 12px;border-bottom:1px solid #eee;vertical-align:top}
tr:hover{background:#f9f9f9}
.badge{padding:3px 8px;border-radius:12px;font-size:.8em;font-weight:bold;color:#fff}
.CRITICAL{background:#ffebee}.badge-CRITICAL{background:#c62828}
.HIGH{background:#fff3e0}.badge-HIGH{background:#e65100}
.MEDIUM{background:#e3f2fd}.badge-MEDIUM{background:#1565c0}
.LOW{background:#f1f8e9}.badge-LOW{background:#2e7d32}
.INFO .badge-INFO{background:#616161}
small{color:#666}
</style>
</head>
<body>
<h1>CloudSentinel Cost Optimization Report</h1>
<div class="summary">
  <p><strong>Findings:</strong> {{total_findings}} &nbsp;
     <strong>Critical:</strong> {{critical_count}} &nbsp;
     <strong>High:</strong> {{high_count}}</p>
  <p class="savings">Est. Monthly Savings: ${{total_savings}}</p>
  <p><strong>Services:</strong> {{services}}</p>
  <p><strong>Regions:</strong> {{regions}}</p>
  <p><strong>Scan Duration:</strong> {{duration}}s</p>
</div>
<table>
<tr>
  <th>Severity</th><th>Service</th><th>Resource</th>
  <th>Region</th><th>Finding</th><th>Category</th><th>Savings/mo</th>
</tr>
{{rows}}
</table>
</body>
</html>"""


def _save_html(result: ScanResult, path: str) -> None:
    rows_html = []
    for f in sorted(result.findings, key=lambda f: _SEVERITY_ORDER.get(f.severity.value, 99)):
        sev = f.severity.value
        savings = f"${f.estimated_monthly_savings:,.2f}" if f.estimated_monthly_savings > 0 else "-"
        rows_html.append(
            f'<tr class="{sev}">'
            f'<td><span class="badge badge-{sev}">{sev}</span></td>'
            f"<td>{f.service}</td>"
            f"<td>{f.resource_name}</td>"
            f"<td>{f.region}</td>"
            f"<td><strong>{f.title}</strong><br><small>{f.description}</small></td>"
            f"<td>{f.category.value}</td>"
            f"<td>{savings}</td>"
            f"</tr>"
        )
    html = (
        _HTML_TEMPLATE
        .replace("{{total_findings}}", str(len(result.findings)))
        .replace("{{critical_count}}", str(result.critical_count))
        .replace("{{high_count}}", str(result.high_count))
        .replace("{{total_savings}}", f"{result.total_monthly_savings:,.2f}")
        .replace("{{services}}", ", ".join(result.scanned_services))
        .replace("{{regions}}", ", ".join(result.scanned_regions))
        .replace("{{duration}}", f"{result.scan_duration_seconds:.1f}")
        .replace("{{rows}}", "\n".join(rows_html))
    )
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)


# ------------------------------------------------------------------ CLI
@click.group()
@click.option("--debug", is_flag=True, help="Enable debug logging")
def main(debug: bool) -> None:
    """CloudSentinel — AI-powered AWS cost optimization and resource monitoring."""
    logging.basicConfig(level=logging.DEBUG if debug else logging.WARNING)


@main.command()
@click.option("--profile", envvar="AWS_PROFILE", default=None, help="AWS profile name")
@click.option("--region", envvar="AWS_DEFAULT_REGION", default=None, help="Primary region")
@click.option("--regions", multiple=True, metavar="REGION", help="Additional regions to scan")
@click.option(
    "--services", multiple=True, metavar="SVC",
    help=f"Services to scan (default: all). Options: {', '.join(ALL_SERVICES)}",
)
@click.option("--output-json", metavar="FILE", default=None, help="Save JSON report")
@click.option("--output-html", metavar="FILE", default=None, help="Save HTML report")
@click.option("--no-ml", is_flag=True, help="Disable ML-based anomaly detection")
@click.option("--days-threshold", default=90, show_default=True,
              help="Days threshold for unused resources")
@click.option("--cpu-threshold", default=5.0, show_default=True,
              help="CPU% threshold for underutilised instances")
def scan(
    profile: Optional[str],
    region: Optional[str],
    regions: tuple[str, ...],
    services: tuple[str, ...],
    output_json: Optional[str],
    output_html: Optional[str],
    no_ml: bool,
    days_threshold: int,
    cpu_threshold: float,
) -> None:
    """Scan AWS resources for cost optimisation opportunities."""
    config = Config(
        profile=profile,
        region=region,
        regions=list(regions),
        services=list(services) if services else ALL_SERVICES,
        days_threshold=days_threshold,
        cpu_threshold=cpu_threshold,
        enable_ai=False,
    )

    console.print(Panel(
        f"Regions : [cyan]{', '.join(config.active_regions)}[/cyan]\n"
        f"Services: [cyan]{', '.join(config.services or ALL_SERVICES)}[/cyan]\n"
        f"ML      : [cyan]{'disabled' if no_ml else 'enabled (Isolation Forest)'}[/cyan]",
        title="[bold]CloudSentinel Scan[/bold]",
        expand=False,
    ))

    try:
        result = _run_scan(config, enable_ml=not no_ml)
    except Exception as exc:
        console.print(f"[red]Scan failed: {exc}[/red]")
        raise SystemExit(1) from exc

    _print_results(result)

    if output_json:
        _save_json(result, output_json)
        console.print(f"[green]JSON report saved: {output_json}[/green]")

    if output_html:
        _save_html(result, output_html)
        console.print(f"[green]HTML report saved: {output_html}[/green]")

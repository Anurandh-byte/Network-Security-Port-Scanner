import sys
import os
import argparse
import time

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.text import Text
from rich import box

from scanner_engine import (
    PORT_DATABASE,
    PRESETS,
    resolve_target,
    PortScannerEngine
)

console = Console(force_terminal=True)


def get_risk_style(risk: str) -> str:
    if risk == "Critical":
        return "bold white on red"
    elif risk == "High":
        return "bold red"
    elif risk == "Medium":
        return "bold yellow"
    elif risk == "Low":
        return "cyan"
    return "dim"

def run_cli_scanner():
    console.print()
    console.print(Panel.fit(
        "[bold cyan]CYBERPORT SCANNER PRO[/bold cyan] [dim]|[/dim] [bold magenta]High-Speed Network Intelligence[/bold magenta]\n"
        "[dim]Multi-threaded socket engine with service fingerprinting & security risk assessment[/dim]",
        box=box.ROUNDED,
        border_style="cyan"
    ))
    console.print()

    parser = argparse.ArgumentParser(description="CyberPort Scanner Pro CLI")
    parser.add_argument("target", nargs="?", default=None, help="Target IP or hostname")
    parser.add_argument("-p", "--preset", choices=list(PRESETS.keys()), default="top20", help="Scan preset")
    parser.add_argument("-r", "--range", default=None, help="Custom port range (e.g. 1-1024 or 80,443,8080)")
    parser.add_argument("-t", "--threads", type=int, default=80, help="Number of worker threads (default: 80)")
    parser.add_argument("--timeout", type=float, default=0.25, help="Socket timeout in seconds (default: 0.25)")

    args = parser.parse_args()

    target = args.target
    if not target:
        target = console.input("[bold green]?[/bold green] [bold white]Enter target IP or hostname (e.g., 127.0.0.1): [/bold white]").strip()
        if not target:
            target = "127.0.0.1"

    # Presets selection if interactive
    preset = args.preset
    if not args.target and not args.range:
        console.print("\n[bold cyan]Select Scan Profile:[/bold cyan]")
        for idx, (k, p) in enumerate(PRESETS.items(), 1):
            console.print(f"  [bold yellow][{idx}][/bold yellow] [bold white]{p['name']}[/bold white] - [dim]{p['description']} ({len(p['ports'])} ports)[/dim]")
        
        choice = console.input("\n[bold green]?[/bold green] [bold white]Choose preset [1-6] (Default: 1): [/bold white]").strip()
        keys = list(PRESETS.keys())
        if choice.isdigit() and 1 <= int(choice) <= len(keys):
            preset = keys[int(choice) - 1]
        else:
            preset = "top20"

    # Resolve ports
    if args.range:
        ports = []
        for part in args.range.split(","):
            if "-" in part:
                s, e = part.split("-")
                ports.extend(range(int(s), int(e) + 1))
            elif part.isdigit():
                ports.append(int(part))
        ports = sorted(list(set(ports)))
    else:
        ports = PRESETS[preset]["ports"]

    console.print(f"\n[cyan][*][/cyan] Resolving target [bold white]{target}[/bold white]...")
    try:
        target_info = resolve_target(target)
    except Exception as e:
        console.print(f"[bold red][!] Error resolving target:[/bold red] {e}")
        sys.exit(1)

    # Display target intel
    intel_table = Table(show_header=False, box=box.SIMPLE)
    intel_table.add_column("Key", style="dim cyan", width=18)
    intel_table.add_column("Value", style="bold white")
    intel_table.add_row("Target Host", target_info["target"])
    intel_table.add_row("Resolved IP", target_info["ip"])
    intel_table.add_row("Reverse PTR", target_info["hostname"])
    intel_table.add_row("Host Latency", f"{target_info['latency_ms']} ms")
    intel_table.add_row("Port Profile", f"{PRESETS.get(preset, {}).get('name', 'Custom')} ({len(ports)} ports)")
    intel_table.add_row("Worker Threads", f"{args.threads} threads (Timeout: {args.timeout}s)")
    console.print(intel_table)
    console.print()

    open_results = []
    
    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=40, complete_style="green", finished_style="bold green"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("• [yellow]{task.completed}/{task.total} ports"),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Scanning target...", total=len(ports))

        def on_event(ev):
            if ev["type"] == "port_scanned":
                progress.advance(task, 1)
                p_data = ev["port_data"]
                if p_data["state"] == "OPEN":
                    open_results.append(p_data)
                    progress.console.print(
                        f"  [bold green][+] OPEN[/bold green] Port [bold yellow]{p_data['port']:<5}[/bold yellow] "
                        f"[cyan]{p_data['service']:<16}[/cyan] "
                        f"[{get_risk_style(p_data['risk'])}]{p_data['risk']:<8}[/{get_risk_style(p_data['risk'])}] "
                        f"[dim]{p_data.get('banner', '') or p_data.get('description', '')}[/dim]"
                    )

        engine = PortScannerEngine(target=target, ports=ports, max_workers=args.threads, timeout=args.timeout)
        summary = engine.run(progress_callback=on_event)

    # Final summary table
    console.print()
    if open_results:
        results_table = Table(
            title=f"Discovered Open Ports ({len(open_results)} found)",
            box=box.HEAVY_EDGE,
            header_style="bold cyan"
        )
        results_table.add_column("Port", style="bold yellow", justify="right", width=8)
        results_table.add_column("Proto", style="dim", width=6)
        results_table.add_column("Service", style="bold white", width=18)
        results_table.add_column("Risk Level", width=12)
        results_table.add_column("Response", justify="right", width=10)
        results_table.add_column("Service Info / Banner", style="dim")

        for item in sorted(open_results, key=lambda x: x["port"]):
            results_table.add_row(
                str(item["port"]),
                item["protocol"],
                item["service"],
                Text(item["risk"], style=get_risk_style(item["risk"])),
                f"{item['response_time_ms']} ms",
                item.get("banner") or item.get("description", "")
            )
        console.print(results_table)
    else:
        console.print(Panel("[bold yellow]No open ports detected in the scanned range.[/bold yellow]", border_style="yellow"))

    console.print(
        f"[bold green]Scan finished in {summary['duration_seconds']}s[/bold green] "
        f"([cyan]{summary['speed_ports_sec']} ports/sec[/cyan]) • "
        f"[bold white]{summary['open_count']}[/bold white] open ports found."
    )
    console.print()

if __name__ == "__main__":
    run_cli_scanner()

from datetime import datetime
from typing import Dict, List
from rich.console import Console
from rich.table import Table
from rich import box

SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
SEVERITY_COLORS = {
    'CRITICAL': 'bold red',
    'HIGH':     'red',
    'MEDIUM':   'yellow',
    'LOW':      'blue',
}


def count_by_severity(findings: List[Dict]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for f in findings:
        sev = f['severity']
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def build_md_report(findings: List[Dict], ai_suggestions: List[str] = None) -> str:
    counts = count_by_severity(findings)
    lines = [
        '# CloudGuard JP — セキュリティスキャンレポート',
        '',
        f'**生成日時:** {datetime.now().strftime("%Y-%m-%d %H:%M")}',
        f'**検出件数:** {len(findings)}件',
        '',
        '## サマリー',
        '',
        '| 重要度 | 件数 |',
        '|--------|------|',
    ]
    for sev in SEVERITY_ORDER:
        count = counts.get(sev, 0)
        if count > 0:
            lines.append(f'| {sev} | {count} |')

    lines += ['', '## 検出一覧', '']
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.index(x['severity'])):
        lines += [
            f"### [{f['severity']}] {f['title']}",
            '',
            f"- **ルールID:** `{f['rule_id']}`",
            f"- **リソース:** `{f['resource']}`",
            f"- **説明:** {f['description']}",
            f"- **対応方法:** {f['fix']}",
            '',
        ]

    if ai_suggestions:
        lines += ['', '## Claude AI 修正提案', '']
        for suggestion in ai_suggestions:
            lines.append(f'- {suggestion}')

    lines += ['', '---', '*CloudGuard JP v0.1.0*']
    return '\n'.join(lines)


def save_md_report(content: str, path: str) -> None:
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)


def print_terminal_report(findings: List[Dict], ai_suggestions: List[str] = None) -> None:
    console = Console(legacy_windows=False)
    counts = count_by_severity(findings)

    console.print('\n[bold cyan]*** CloudGuard JP -- Security Scan Report[/bold cyan]')
    console.print('=' * 60)

    total = len(findings)
    critical = counts.get('CRITICAL', 0)
    high = counts.get('HIGH', 0)
    console.print(
        f'Findings: {total}  '
        f'[bold red]CRITICAL:{critical}[/bold red]  '
        f'[red]HIGH:{high}[/red]  '
        f'[yellow]MEDIUM:{counts.get("MEDIUM", 0)}[/yellow]  '
        f'[blue]LOW:{counts.get("LOW", 0)}[/blue]\n'
    )

    if not findings:
        console.print('[bold green]No findings. Your environment is clean![/bold green]')
        return

    table = Table(box=box.SIMPLE, show_header=True, header_style='bold magenta')
    table.add_column('Severity', style='bold', width=10)
    table.add_column('Rule ID', width=28)
    table.add_column('Resource', width=22)
    table.add_column('Title')

    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.index(x['severity'])):
        color = SEVERITY_COLORS.get(f['severity'], '')
        table.add_row(
            f'[{color}]{f["severity"]}[/{color}]',
            f['rule_id'],
            f['resource'],
            f['title'],
        )

    console.print(table)

    if ai_suggestions:
        console.print('[bold bright_cyan]Claude AI 修正提案:[/bold bright_cyan]')
        for suggestion in ai_suggestions:
            console.print(f'  {suggestion}')
        console.print()

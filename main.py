import argparse
from datetime import datetime
from pathlib import Path

from scanner import scan_s3, scan_iam
from reporter import build_md_report, save_md_report, print_terminal_report
from demo_data import get_demo_findings


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description='CloudGuard JP — AWSセキュリティスキャンCLI')
    parser.add_argument('--profile', default='default', help='AWS profile名')
    parser.add_argument('--services', nargs='+', default=['s3', 'iam'],
                        choices=['s3', 'iam'], help='スキャン対象サービス')
    parser.add_argument('--output-md', action='store_true', help='MDレポートを出力')
    parser.add_argument('--demo', action='store_true', help='デモデータで動作確認（AWS不要）')
    return parser.parse_args(argv)


def run(profile: str, services: list, output_md: bool, demo: bool = False) -> None:
    if demo:
        findings = get_demo_findings()
    else:
        findings = []
        if 's3' in services:
            findings.extend(scan_s3(profile))
        if 'iam' in services:
            findings.extend(scan_iam(profile))

    print_terminal_report(findings)

    if output_md:
        content = build_md_report(findings)
        filename = f"cloudguard_report_{datetime.now().strftime('%Y%m%d')}.md"
        output_path = str(Path('C:/claude_c') / filename)
        save_md_report(content, output_path)
        print(f'\n MDレポートを保存しました: {output_path}')


if __name__ == '__main__':
    args = parse_args()
    run(profile=args.profile, services=args.services,
        output_md=args.output_md, demo=args.demo)

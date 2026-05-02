from typing import Dict, List
import anthropic

FINDINGS_ANALYSIS_PROMPT = """あなたはAWSセキュリティの専門家です。
以下のセキュリティスキャン結果を分析し、優先度の高い修正アクションを3件、日本語で簡潔に提示してください。

【スキャン結果】
検出件数: {total}件
重要度別: CRITICAL={critical}件 / HIGH={high}件 / MEDIUM={medium}件 / LOW={low}件

主な検出内容:
{findings_summary}

【回答形式】
1. [具体的な修正アクション] → [期待効果・理由]
2. [具体的な修正アクション] → [期待効果・理由]
3. [具体的な修正アクション] → [期待効果・理由]

CRITICALとHIGHを優先し、実施可能な具体的な手順で提案してください。"""


def analyze_findings(findings: List[Dict]) -> List[str]:
    client = anthropic.Anthropic()

    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in findings:
        sev = f.get('severity', 'LOW')
        if sev in severity_counts:
            severity_counts[sev] += 1

    top_findings = sorted(
        findings,
        key=lambda f: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].index(f.get('severity', 'LOW'))
    )[:6]

    summary_lines = [
        f"  [{f['severity']}] {f.get('rule_id', '?')}: {f.get('description', '')} ({f.get('resource', '')})"
        for f in top_findings
    ] or ['  検出なし']

    prompt = FINDINGS_ANALYSIS_PROMPT.format(
        total=len(findings),
        critical=severity_counts['CRITICAL'],
        high=severity_counts['HIGH'],
        medium=severity_counts['MEDIUM'],
        low=severity_counts['LOW'],
        findings_summary='\n'.join(summary_lines),
    )

    response = client.messages.create(
        model='claude-sonnet-4-6',
        max_tokens=500,
        messages=[{'role': 'user', 'content': prompt}],
    )

    lines = response.content[0].text.strip().split('\n')
    return [line.strip() for line in lines if line.strip()]

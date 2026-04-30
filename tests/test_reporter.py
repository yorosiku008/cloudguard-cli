import pytest
from unittest.mock import MagicMock, patch

SAMPLE_FINDINGS = [
    {
        'rule_id': 'S3_PUBLIC_ACL',
        'severity': 'HIGH',
        'resource': 'my-public-bucket',
        'title': 'S3バケットが公開ACLに設定されています',
        'description': '全インターネットからのReadアクセスが許可されています',
        'fix': 'ACLをprivateに変更し、バケットポリシーでアクセス制御してください',
    },
    {
        'rule_id': 'S3_VERSIONING_DISABLED',
        'severity': 'MEDIUM',
        'resource': 'my-data-bucket',
        'title': 'S3バケットのバージョニングが無効です',
        'description': 'バージョニングが無効だとオブジェクトの誤削除から復元できません',
        'fix': 'S3コンソールからバージョニングを有効化してください',
    },
    {
        'rule_id': 'IAM_ROOT_ACCESS_KEY',
        'severity': 'CRITICAL',
        'resource': 'root',
        'title': 'rootアカウントにアクセスキーが存在します',
        'description': 'rootアクセスキーは最大権限を持ち、漏洩時のリスクが極めて高いです',
        'fix': 'rootアクセスキーをすぐに削除してください',
    },
]


def test_build_md_report_returns_string():
    from reporter import build_md_report
    result = build_md_report(SAMPLE_FINDINGS)
    assert isinstance(result, str)
    assert len(result) > 0


def test_build_md_report_includes_findings():
    from reporter import build_md_report
    result = build_md_report(SAMPLE_FINDINGS)
    assert 'S3_PUBLIC_ACL' in result
    assert 'CRITICAL' in result
    assert 'my-public-bucket' in result


def test_build_md_report_includes_summary():
    from reporter import build_md_report
    result = build_md_report(SAMPLE_FINDINGS)
    assert 'CRITICAL' in result
    assert 'HIGH' in result
    assert 'MEDIUM' in result


def test_count_by_severity():
    from reporter import count_by_severity
    counts = count_by_severity(SAMPLE_FINDINGS)
    assert counts['CRITICAL'] == 1
    assert counts['HIGH'] == 1
    assert counts['MEDIUM'] == 1
    assert counts.get('LOW', 0) == 0


def test_count_by_severity_empty():
    from reporter import count_by_severity
    counts = count_by_severity([])
    assert counts.get('CRITICAL', 0) == 0


@patch('reporter.Console')
def test_print_terminal_report_calls_console(mock_console_cls):
    mock_console = MagicMock()
    mock_console_cls.return_value = mock_console

    from reporter import print_terminal_report
    print_terminal_report(SAMPLE_FINDINGS)

    assert mock_console.print.called


def test_save_md_report_writes_file(tmp_path):
    from reporter import save_md_report
    content = "# テストレポート"
    path = str(tmp_path / "report.md")
    save_md_report(content, path)
    with open(path, encoding='utf-8') as f:
        assert f.read() == content

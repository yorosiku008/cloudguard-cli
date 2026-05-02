import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import MagicMock, patch

SAMPLE_FINDINGS = [
    {'rule_id': 'IAM_ROOT_ACCESS_KEY', 'severity': 'CRITICAL',
     'description': 'rootアカウントにアクセスキーが存在します', 'resource': 'root'},
    {'rule_id': 'S3_PUBLIC_ACL', 'severity': 'HIGH',
     'description': 'S3バケットが公開ACLに設定されています', 'resource': 'my-bucket'},
    {'rule_id': 'EC2_SG_SSH_OPEN', 'severity': 'HIGH',
     'description': 'SSHポートが全公開されています', 'resource': 'sg-12345'},
]


def make_mock_response(text: str):
    mock_content = MagicMock()
    mock_content.text = text
    mock_response = MagicMock()
    mock_response.content = [mock_content]
    return mock_response


@patch('analyzer.anthropic.Anthropic')
def test_analyze_findings_returns_list(mock_cls):
    mock_client = MagicMock()
    mock_cls.return_value = mock_client
    mock_client.messages.create.return_value = make_mock_response(
        "1. rootアクセスキーを即時削除してください → CRITICAL対応\n"
        "2. S3バケットのACLをプライベートに変更してください → データ漏洩防止\n"
        "3. SSHポートのCIDRを社内IPに限定してください → 不正アクセス防止"
    )
    from analyzer import analyze_findings
    result = analyze_findings(SAMPLE_FINDINGS)
    assert isinstance(result, list)
    assert len(result) >= 1


@patch('analyzer.anthropic.Anthropic')
def test_analyze_findings_returns_strings(mock_cls):
    mock_client = MagicMock()
    mock_cls.return_value = mock_client
    mock_client.messages.create.return_value = make_mock_response("1. 提案A\n2. 提案B")
    from analyzer import analyze_findings
    result = analyze_findings(SAMPLE_FINDINGS)
    for item in result:
        assert isinstance(item, str) and len(item) > 0


@patch('analyzer.anthropic.Anthropic')
def test_analyze_findings_calls_claude(mock_cls):
    mock_client = MagicMock()
    mock_cls.return_value = mock_client
    mock_client.messages.create.return_value = make_mock_response("1. 提案")
    from analyzer import analyze_findings
    analyze_findings(SAMPLE_FINDINGS)
    mock_client.messages.create.assert_called_once()
    kwargs = mock_client.messages.create.call_args[1]
    assert kwargs['model'] == 'claude-sonnet-4-6'


@patch('analyzer.anthropic.Anthropic')
def test_analyze_findings_prompt_includes_severity(mock_cls):
    mock_client = MagicMock()
    mock_cls.return_value = mock_client
    mock_client.messages.create.return_value = make_mock_response("1. 提案")
    from analyzer import analyze_findings
    analyze_findings(SAMPLE_FINDINGS)
    kwargs = mock_client.messages.create.call_args[1]
    prompt = kwargs['messages'][0]['content']
    assert 'CRITICAL' in prompt or 'HIGH' in prompt


@patch('analyzer.anthropic.Anthropic')
def test_analyze_findings_empty_returns_list(mock_cls):
    mock_client = MagicMock()
    mock_cls.return_value = mock_client
    mock_client.messages.create.return_value = make_mock_response("問題は検出されませんでした。")
    from analyzer import analyze_findings
    result = analyze_findings([])
    assert isinstance(result, list)

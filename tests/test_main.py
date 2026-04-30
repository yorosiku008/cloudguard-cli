import pytest
from unittest.mock import MagicMock, patch

SAMPLE_FINDINGS = [
    {'rule_id': 'S3_PUBLIC_ACL', 'severity': 'HIGH',
     'resource': 'bucket', 'title': 'S3公開ACL', 'description': '', 'fix': ''},
]


def test_parse_args_defaults():
    from main import parse_args
    args = parse_args([])
    assert args.profile == 'default'
    assert args.services == ['s3', 'iam']
    assert args.output_md is False
    assert args.demo is False


def test_parse_args_custom_profile():
    from main import parse_args
    args = parse_args(['--profile', 'mycompany'])
    assert args.profile == 'mycompany'


def test_parse_args_services():
    from main import parse_args
    args = parse_args(['--services', 's3'])
    assert args.services == ['s3']


def test_parse_args_demo_flag():
    from main import parse_args
    args = parse_args(['--demo'])
    assert args.demo is True


@patch('main.print_terminal_report')
@patch('main.scan_iam')
@patch('main.scan_s3')
def test_run_calls_scanners(mock_s3, mock_iam, mock_print):
    mock_s3.return_value = SAMPLE_FINDINGS
    mock_iam.return_value = []

    from main import run
    run(profile='default', services=['s3', 'iam'], output_md=False, demo=False)

    mock_s3.assert_called_once_with('default')
    mock_iam.assert_called_once_with('default')
    mock_print.assert_called_once()


@patch('main.print_terminal_report')
@patch('main.get_demo_findings')
def test_run_demo_skips_aws(mock_demo, mock_print):
    mock_demo.return_value = SAMPLE_FINDINGS

    from main import run
    with patch('main.scan_s3') as mock_s3, patch('main.scan_iam') as mock_iam:
        run(profile='default', services=['s3', 'iam'], output_md=False, demo=True)
        mock_s3.assert_not_called()
        mock_iam.assert_not_called()
    mock_demo.assert_called_once()

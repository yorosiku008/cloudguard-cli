import pytest
from unittest.mock import MagicMock, patch

SAMPLE_FINDINGS = [
    {'rule_id': 'S3_PUBLIC_ACL', 'severity': 'HIGH',
     'resource': 'bucket', 'title': 'S3公開ACL', 'description': '', 'fix': ''},
    {'rule_id': 'IAM_ROOT_ACCESS_KEY', 'severity': 'CRITICAL',
     'resource': 'root', 'title': 'rootキー', 'description': '', 'fix': ''},
    {'rule_id': 'S3_VERSIONING_DISABLED', 'severity': 'MEDIUM',
     'resource': 'bucket', 'title': 'バージョニング無効', 'description': '', 'fix': ''},
]


def test_parse_args_defaults():
    from main import parse_args
    args = parse_args([])
    assert args.profile == 'default'
    assert set(args.services) == {'s3', 'iam', 'ec2', 'cloudtrail'}
    assert args.output_md is False
    assert args.demo is False
    assert args.severity is None


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


def test_parse_args_severity_filter():
    from main import parse_args
    args = parse_args(['--severity', 'CRITICAL', 'HIGH'])
    assert args.severity == ['CRITICAL', 'HIGH']


@patch('main.print_terminal_report')
@patch('main.scan_cloudtrail')
@patch('main.scan_ec2')
@patch('main.scan_iam')
@patch('main.scan_s3')
def test_run_calls_scanners(mock_s3, mock_iam, mock_ec2, mock_ct, mock_print):
    mock_s3.return_value = SAMPLE_FINDINGS[:1]
    mock_iam.return_value = []
    mock_ec2.return_value = []
    mock_ct.return_value = []

    from main import run
    run(profile='default', services=['s3', 'iam', 'ec2', 'cloudtrail'],
        output_md=False, demo=False)

    mock_s3.assert_called_once_with('default')
    mock_iam.assert_called_once_with('default')
    mock_ec2.assert_called_once_with('default')
    mock_ct.assert_called_once_with('default')
    mock_print.assert_called_once()


@patch('main.print_terminal_report')
@patch('main.get_demo_findings')
def test_run_demo_skips_aws(mock_demo, mock_print):
    mock_demo.return_value = SAMPLE_FINDINGS

    from main import run
    with patch('main.scan_s3') as ms3, patch('main.scan_iam') as mi, \
         patch('main.scan_ec2') as me, patch('main.scan_cloudtrail') as mc:
        run(profile='default', services=['s3', 'iam', 'ec2', 'cloudtrail'],
            output_md=False, demo=True)
        ms3.assert_not_called()
        mi.assert_not_called()
        me.assert_not_called()
        mc.assert_not_called()
    mock_demo.assert_called_once()


@patch('main.print_terminal_report')
@patch('main.get_demo_findings')
def test_run_severity_filter(mock_demo, mock_print):
    mock_demo.return_value = SAMPLE_FINDINGS

    from main import run
    run(profile='default', services=['s3', 'iam'], output_md=False,
        demo=True, severity=['CRITICAL'])

    shown = mock_print.call_args[0][0]
    assert all(f['severity'] == 'CRITICAL' for f in shown)
    assert len(shown) == 1


@patch('main.print_terminal_report')
@patch('main.scan_cloudtrail')
@patch('main.scan_ec2')
@patch('main.scan_iam')
@patch('main.scan_s3')
def test_run_selected_services_only(mock_s3, mock_iam, mock_ec2, mock_ct, mock_print):
    mock_s3.return_value = []
    mock_session = MagicMock()

    from main import run
    run(profile='default', services=['s3'], output_md=False, demo=False)

    mock_s3.assert_called_once()
    mock_iam.assert_not_called()
    mock_ec2.assert_not_called()
    mock_ct.assert_not_called()

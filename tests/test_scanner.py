import pytest
from unittest.mock import MagicMock, patch


def make_s3_bucket(name, public_acl=False, versioning=False, logging=False):
    return {
        'Name': name,
        'public_acl': public_acl,
        'versioning': versioning,
        'logging': logging,
    }


@patch('scanner.boto3.Session')
def test_scan_s3_returns_list(mock_session):
    mock_client = MagicMock()
    mock_session.return_value.client.return_value = mock_client
    mock_client.list_buckets.return_value = {
        'Buckets': [{'Name': 'my-bucket'}]
    }
    mock_client.get_bucket_acl.return_value = {
        'Grants': []
    }
    mock_client.get_bucket_versioning.return_value = {}
    mock_client.get_bucket_logging.return_value = {}

    from scanner import scan_s3
    result = scan_s3('default')
    assert isinstance(result, list)


@patch('scanner.boto3.Session')
def test_scan_s3_detects_public_acl(mock_session):
    mock_client = MagicMock()
    mock_session.return_value.client.return_value = mock_client
    mock_client.list_buckets.return_value = {
        'Buckets': [{'Name': 'public-bucket'}]
    }
    mock_client.get_bucket_acl.return_value = {
        'Grants': [
            {'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'},
             'Permission': 'READ'}
        ]
    }
    mock_client.get_bucket_versioning.return_value = {}
    mock_client.get_bucket_logging.return_value = {}

    from scanner import scan_s3
    findings = scan_s3('default')

    public_findings = [f for f in findings if f['rule_id'] == 'S3_PUBLIC_ACL']
    assert len(public_findings) == 1
    assert public_findings[0]['severity'] == 'HIGH'
    assert public_findings[0]['resource'] == 'public-bucket'


@patch('scanner.boto3.Session')
def test_scan_s3_detects_versioning_disabled(mock_session):
    mock_client = MagicMock()
    mock_session.return_value.client.return_value = mock_client
    mock_client.list_buckets.return_value = {
        'Buckets': [{'Name': 'no-version-bucket'}]
    }
    mock_client.get_bucket_acl.return_value = {'Grants': []}
    mock_client.get_bucket_versioning.return_value = {}
    mock_client.get_bucket_logging.return_value = {}

    from scanner import scan_s3
    findings = scan_s3('default')

    version_findings = [f for f in findings if f['rule_id'] == 'S3_VERSIONING_DISABLED']
    assert len(version_findings) == 1
    assert version_findings[0]['severity'] == 'MEDIUM'


@patch('scanner.boto3.Session')
def test_scan_s3_no_findings_for_compliant_bucket(mock_session):
    mock_client = MagicMock()
    mock_session.return_value.client.return_value = mock_client
    mock_client.list_buckets.return_value = {
        'Buckets': [{'Name': 'safe-bucket'}]
    }
    mock_client.get_bucket_acl.return_value = {'Grants': []}
    mock_client.get_bucket_versioning.return_value = {'Status': 'Enabled'}
    mock_client.get_bucket_logging.return_value = {
        'LoggingEnabled': {'TargetBucket': 'log-bucket'}
    }

    from scanner import scan_s3
    findings = scan_s3('default')
    assert len(findings) == 0


@patch('scanner.boto3.Session')
def test_scan_iam_detects_root_access_key(mock_session):
    mock_client = MagicMock()
    mock_session.return_value.client.return_value = mock_client
    mock_client.get_account_summary.return_value = {
        'SummaryMap': {'AccountAccessKeysPresent': 1}
    }
    mock_client.list_users.return_value = {'Users': [], 'IsTruncated': False}

    from scanner import scan_iam
    findings = scan_iam('default')

    root_findings = [f for f in findings if f['rule_id'] == 'IAM_ROOT_ACCESS_KEY']
    assert len(root_findings) == 1
    assert root_findings[0]['severity'] == 'CRITICAL'


@patch('scanner.boto3.Session')
def test_scan_iam_no_root_finding_when_no_key(mock_session):
    mock_client = MagicMock()
    mock_session.return_value.client.return_value = mock_client
    mock_client.get_account_summary.return_value = {
        'SummaryMap': {'AccountAccessKeysPresent': 0}
    }
    mock_client.list_users.return_value = {'Users': [], 'IsTruncated': False}

    from scanner import scan_iam
    findings = scan_iam('default')

    root_findings = [f for f in findings if f['rule_id'] == 'IAM_ROOT_ACCESS_KEY']
    assert len(root_findings) == 0

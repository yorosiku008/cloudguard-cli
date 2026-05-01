import pytest
from unittest.mock import MagicMock, patch


def _make_compliant_s3_client():
    client = MagicMock()
    client.list_buckets.return_value = {'Buckets': [{'Name': 'safe-bucket'}]}
    client.get_bucket_acl.return_value = {'Grants': []}
    client.get_public_access_block.return_value = {'PublicAccessBlockConfiguration': {
        'BlockPublicAcls': True, 'IgnorePublicAcls': True,
        'BlockPublicPolicy': True, 'RestrictPublicBuckets': True,
    }}
    client.get_bucket_versioning.return_value = {'Status': 'Enabled'}
    client.get_bucket_encryption.return_value = {'ServerSideEncryptionConfiguration': {}}
    client.get_bucket_logging.return_value = {'LoggingEnabled': {'TargetBucket': 'log-bucket'}}
    return client


@patch('scanner.boto3.Session')
def test_scan_s3_returns_list(mock_session):
    mock_session.return_value.client.return_value = _make_compliant_s3_client()
    from scanner import scan_s3
    result = scan_s3('default')
    assert isinstance(result, list)


@patch('scanner.boto3.Session')
def test_scan_s3_no_findings_for_compliant_bucket(mock_session):
    mock_session.return_value.client.return_value = _make_compliant_s3_client()
    from scanner import scan_s3
    findings = scan_s3('default')
    assert len(findings) == 0


@patch('scanner.boto3.Session')
def test_scan_s3_detects_public_acl(mock_session):
    client = _make_compliant_s3_client()
    client.list_buckets.return_value = {'Buckets': [{'Name': 'public-bucket'}]}
    client.get_bucket_acl.return_value = {'Grants': [
        {'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'}, 'Permission': 'READ'}
    ]}
    mock_session.return_value.client.return_value = client

    from scanner import scan_s3
    findings = scan_s3('default')
    public_findings = [f for f in findings if f['rule_id'] == 'S3_PUBLIC_ACL']
    assert len(public_findings) == 1
    assert public_findings[0]['severity'] == 'HIGH'
    assert public_findings[0]['resource'] == 'public-bucket'


@patch('scanner.boto3.Session')
def test_scan_s3_detects_public_block_disabled(mock_session):
    client = _make_compliant_s3_client()
    client.list_buckets.return_value = {'Buckets': [{'Name': 'no-block-bucket'}]}
    client.get_public_access_block.return_value = {'PublicAccessBlockConfiguration': {
        'BlockPublicAcls': False, 'IgnorePublicAcls': True,
        'BlockPublicPolicy': True, 'RestrictPublicBuckets': True,
    }}
    mock_session.return_value.client.return_value = client

    from scanner import scan_s3
    findings = scan_s3('default')
    block_findings = [f for f in findings if f['rule_id'] == 'S3_PUBLIC_BLOCK_DISABLED']
    assert len(block_findings) == 1
    assert block_findings[0]['severity'] == 'HIGH'


@patch('scanner.boto3.Session')
def test_scan_s3_detects_public_block_missing(mock_session):
    client = _make_compliant_s3_client()
    client.list_buckets.return_value = {'Buckets': [{'Name': 'no-block-bucket'}]}
    client.get_public_access_block.side_effect = Exception('NoSuchPublicAccessBlockConfiguration')
    mock_session.return_value.client.return_value = client

    from scanner import scan_s3
    findings = scan_s3('default')
    block_findings = [f for f in findings if f['rule_id'] == 'S3_PUBLIC_BLOCK_DISABLED']
    assert len(block_findings) == 1


@patch('scanner.boto3.Session')
def test_scan_s3_detects_versioning_disabled(mock_session):
    client = _make_compliant_s3_client()
    client.list_buckets.return_value = {'Buckets': [{'Name': 'no-version-bucket'}]}
    client.get_bucket_versioning.return_value = {}
    mock_session.return_value.client.return_value = client

    from scanner import scan_s3
    findings = scan_s3('default')
    version_findings = [f for f in findings if f['rule_id'] == 'S3_VERSIONING_DISABLED']
    assert len(version_findings) == 1
    assert version_findings[0]['severity'] == 'MEDIUM'


@patch('scanner.boto3.Session')
def test_scan_s3_detects_encryption_disabled(mock_session):
    client = _make_compliant_s3_client()
    client.list_buckets.return_value = {'Buckets': [{'Name': 'no-enc-bucket'}]}
    client.get_bucket_encryption.side_effect = Exception('ServerSideEncryptionConfigurationNotFoundError')
    mock_session.return_value.client.return_value = client

    from scanner import scan_s3
    findings = scan_s3('default')
    enc_findings = [f for f in findings if f['rule_id'] == 'S3_ENCRYPTION_DISABLED']
    assert len(enc_findings) == 1
    assert enc_findings[0]['severity'] == 'MEDIUM'


@patch('scanner.boto3.Session')
def test_scan_iam_detects_root_access_key(mock_session):
    client = MagicMock()
    client.get_account_summary.return_value = {
        'SummaryMap': {'AccountAccessKeysPresent': 1, 'AccountMFAEnabled': 1}
    }
    client.get_account_password_policy.return_value = {}
    mock_session.return_value.client.return_value = client

    from scanner import scan_iam
    findings = scan_iam('default')
    root_findings = [f for f in findings if f['rule_id'] == 'IAM_ROOT_ACCESS_KEY']
    assert len(root_findings) == 1
    assert root_findings[0]['severity'] == 'CRITICAL'


@patch('scanner.boto3.Session')
def test_scan_iam_detects_root_mfa_disabled(mock_session):
    client = MagicMock()
    client.get_account_summary.return_value = {
        'SummaryMap': {'AccountAccessKeysPresent': 0, 'AccountMFAEnabled': 0}
    }
    client.get_account_password_policy.return_value = {}
    mock_session.return_value.client.return_value = client

    from scanner import scan_iam
    findings = scan_iam('default')
    mfa_findings = [f for f in findings if f['rule_id'] == 'IAM_ROOT_MFA_DISABLED']
    assert len(mfa_findings) == 1
    assert mfa_findings[0]['severity'] == 'CRITICAL'


@patch('scanner.boto3.Session')
def test_scan_iam_detects_missing_password_policy(mock_session):
    client = MagicMock()
    client.get_account_summary.return_value = {
        'SummaryMap': {'AccountAccessKeysPresent': 0, 'AccountMFAEnabled': 1}
    }
    client.get_account_password_policy.side_effect = Exception('NoSuchEntity')
    mock_session.return_value.client.return_value = client

    from scanner import scan_iam
    findings = scan_iam('default')
    pw_findings = [f for f in findings if f['rule_id'] == 'IAM_PASSWORD_POLICY_MISSING']
    assert len(pw_findings) == 1
    assert pw_findings[0]['severity'] == 'MEDIUM'


@patch('scanner.boto3.Session')
def test_scan_iam_no_root_finding_when_compliant(mock_session):
    client = MagicMock()
    client.get_account_summary.return_value = {
        'SummaryMap': {'AccountAccessKeysPresent': 0, 'AccountMFAEnabled': 1}
    }
    client.get_account_password_policy.return_value = {}
    mock_session.return_value.client.return_value = client

    from scanner import scan_iam
    findings = scan_iam('default')
    assert len(findings) == 0

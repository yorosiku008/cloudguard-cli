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
    assert isinstance(scan_s3('default'), list)


@patch('scanner.boto3.Session')
def test_scan_s3_no_findings_for_compliant_bucket(mock_session):
    mock_session.return_value.client.return_value = _make_compliant_s3_client()
    from scanner import scan_s3
    assert len(scan_s3('default')) == 0


@patch('scanner.boto3.Session')
def test_scan_s3_detects_public_acl(mock_session):
    client = _make_compliant_s3_client()
    client.list_buckets.return_value = {'Buckets': [{'Name': 'public-bucket'}]}
    client.get_bucket_acl.return_value = {'Grants': [
        {'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'}, 'Permission': 'READ'}
    ]}
    mock_session.return_value.client.return_value = client
    from scanner import scan_s3
    findings = [f for f in scan_s3('default') if f['rule_id'] == 'S3_PUBLIC_ACL']
    assert len(findings) == 1 and findings[0]['severity'] == 'HIGH'


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
    findings = [f for f in scan_s3('default') if f['rule_id'] == 'S3_PUBLIC_BLOCK_DISABLED']
    assert len(findings) == 1 and findings[0]['severity'] == 'HIGH'


@patch('scanner.boto3.Session')
def test_scan_s3_detects_public_block_missing(mock_session):
    client = _make_compliant_s3_client()
    client.list_buckets.return_value = {'Buckets': [{'Name': 'no-block-bucket'}]}
    client.get_public_access_block.side_effect = Exception('NoSuchPublicAccessBlockConfiguration')
    mock_session.return_value.client.return_value = client
    from scanner import scan_s3
    findings = [f for f in scan_s3('default') if f['rule_id'] == 'S3_PUBLIC_BLOCK_DISABLED']
    assert len(findings) == 1


@patch('scanner.boto3.Session')
def test_scan_s3_detects_versioning_disabled(mock_session):
    client = _make_compliant_s3_client()
    client.list_buckets.return_value = {'Buckets': [{'Name': 'no-version-bucket'}]}
    client.get_bucket_versioning.return_value = {}
    mock_session.return_value.client.return_value = client
    from scanner import scan_s3
    findings = [f for f in scan_s3('default') if f['rule_id'] == 'S3_VERSIONING_DISABLED']
    assert len(findings) == 1 and findings[0]['severity'] == 'MEDIUM'


@patch('scanner.boto3.Session')
def test_scan_s3_detects_encryption_disabled(mock_session):
    client = _make_compliant_s3_client()
    client.list_buckets.return_value = {'Buckets': [{'Name': 'no-enc-bucket'}]}
    client.get_bucket_encryption.side_effect = Exception('NoEncryption')
    mock_session.return_value.client.return_value = client
    from scanner import scan_s3
    findings = [f for f in scan_s3('default') if f['rule_id'] == 'S3_ENCRYPTION_DISABLED']
    assert len(findings) == 1 and findings[0]['severity'] == 'MEDIUM'


@patch('scanner.boto3.Session')
def test_scan_iam_detects_root_access_key(mock_session):
    client = MagicMock()
    client.get_account_summary.return_value = {
        'SummaryMap': {'AccountAccessKeysPresent': 1, 'AccountMFAEnabled': 1}
    }
    client.get_account_password_policy.return_value = {}
    mock_session.return_value.client.return_value = client
    from scanner import scan_iam
    findings = [f for f in scan_iam('default') if f['rule_id'] == 'IAM_ROOT_ACCESS_KEY']
    assert len(findings) == 1 and findings[0]['severity'] == 'CRITICAL'


@patch('scanner.boto3.Session')
def test_scan_iam_detects_root_mfa_disabled(mock_session):
    client = MagicMock()
    client.get_account_summary.return_value = {
        'SummaryMap': {'AccountAccessKeysPresent': 0, 'AccountMFAEnabled': 0}
    }
    client.get_account_password_policy.return_value = {}
    mock_session.return_value.client.return_value = client
    from scanner import scan_iam
    findings = [f for f in scan_iam('default') if f['rule_id'] == 'IAM_ROOT_MFA_DISABLED']
    assert len(findings) == 1 and findings[0]['severity'] == 'CRITICAL'


@patch('scanner.boto3.Session')
def test_scan_iam_detects_missing_password_policy(mock_session):
    client = MagicMock()
    client.get_account_summary.return_value = {
        'SummaryMap': {'AccountAccessKeysPresent': 0, 'AccountMFAEnabled': 1}
    }
    client.get_account_password_policy.side_effect = Exception('NoSuchEntity')
    mock_session.return_value.client.return_value = client
    from scanner import scan_iam
    findings = [f for f in scan_iam('default') if f['rule_id'] == 'IAM_PASSWORD_POLICY_MISSING']
    assert len(findings) == 1 and findings[0]['severity'] == 'MEDIUM'


@patch('scanner.boto3.Session')
def test_scan_iam_no_findings_when_compliant(mock_session):
    client = MagicMock()
    client.get_account_summary.return_value = {
        'SummaryMap': {'AccountAccessKeysPresent': 0, 'AccountMFAEnabled': 1}
    }
    client.get_account_password_policy.return_value = {}
    mock_session.return_value.client.return_value = client
    from scanner import scan_iam
    assert len(scan_iam('default')) == 0


@patch('scanner.boto3.Session')
def test_scan_ec2_detects_open_ssh(mock_session):
    client = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [{'SecurityGroups': [{
        'GroupId': 'sg-0abc1234',
        'GroupName': 'launch-wizard-1',
        'IpPermissions': [{
            'FromPort': 22, 'ToPort': 22, 'IpProtocol': 'tcp',
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}],
            'Ipv6Ranges': [],
        }]
    }]}]
    client.get_paginator.return_value = paginator
    mock_session.return_value.client.return_value = client
    from scanner import scan_ec2
    findings = scan_ec2('default')
    ssh_findings = [f for f in findings if f['rule_id'] == 'EC2_SG_SSH_OPEN']
    assert len(ssh_findings) == 1 and ssh_findings[0]['severity'] == 'HIGH'


@patch('scanner.boto3.Session')
def test_scan_ec2_no_findings_for_restricted_sg(mock_session):
    client = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [{'SecurityGroups': [{
        'GroupId': 'sg-safe',
        'GroupName': 'safe-sg',
        'IpPermissions': [{
            'FromPort': 22, 'ToPort': 22, 'IpProtocol': 'tcp',
            'IpRanges': [{'CidrIp': '10.0.0.0/8'}],
            'Ipv6Ranges': [],
        }]
    }]}]
    client.get_paginator.return_value = paginator
    mock_session.return_value.client.return_value = client
    from scanner import scan_ec2
    assert len(scan_ec2('default')) == 0


@patch('scanner.boto3.Session')
def test_scan_cloudtrail_detects_not_enabled(mock_session):
    client = MagicMock()
    client.describe_trails.return_value = {'trailList': []}
    mock_session.return_value.client.return_value = client
    from scanner import scan_cloudtrail
    findings = scan_cloudtrail('default')
    assert len(findings) == 1 and findings[0]['rule_id'] == 'CLOUDTRAIL_NOT_ENABLED'
    assert findings[0]['severity'] == 'HIGH'


@patch('scanner.boto3.Session')
def test_scan_cloudtrail_detects_single_region(mock_session):
    client = MagicMock()
    client.describe_trails.return_value = {'trailList': [
        {'TrailARN': 'arn:aws:cloudtrail:ap-northeast-1:123:trail/my-trail',
         'IsMultiRegionTrail': False}
    ]}
    mock_session.return_value.client.return_value = client
    from scanner import scan_cloudtrail
    findings = scan_cloudtrail('default')
    assert len(findings) == 1 and findings[0]['rule_id'] == 'CLOUDTRAIL_NOT_MULTIREGION'


@patch('scanner.boto3.Session')
def test_scan_cloudtrail_no_findings_when_compliant(mock_session):
    client = MagicMock()
    client.describe_trails.return_value = {'trailList': [
        {'TrailARN': 'arn:aws:cloudtrail:us-east-1:123:trail/my-trail',
         'IsMultiRegionTrail': True}
    ]}
    mock_session.return_value.client.return_value = client
    from scanner import scan_cloudtrail
    assert len(scan_cloudtrail('default')) == 0

import boto3
from typing import Dict, List

PUBLIC_URIS = {
    'http://acs.amazonaws.com/groups/global/AllUsers',
    'http://acs.amazonaws.com/groups/global/AuthenticatedUsers',
}


def scan_s3(profile: str) -> List[Dict]:
    session = boto3.Session(profile_name=profile)
    client = session.client('s3')
    findings = []

    buckets = client.list_buckets().get('Buckets', [])
    for bucket in buckets:
        name = bucket['Name']
        findings.extend(_check_s3_acl(client, name))
        findings.extend(_check_s3_public_block(client, name))
        findings.extend(_check_s3_versioning(client, name))
        findings.extend(_check_s3_encryption(client, name))
        findings.extend(_check_s3_logging(client, name))

    return findings


def _check_s3_acl(client, bucket_name: str) -> List[Dict]:
    acl = client.get_bucket_acl(Bucket=bucket_name)
    for grant in acl.get('Grants', []):
        uri = grant.get('Grantee', {}).get('URI', '')
        if uri in PUBLIC_URIS:
            return [_finding(
                rule_id='S3_PUBLIC_ACL',
                severity='HIGH',
                resource=bucket_name,
                title='S3バケットが公開ACLに設定されています',
                description='全インターネットからのアクセスが許可されています',
                fix='ACLをprivateに変更し、バケットポリシーで制御してください',
            )]
    return []


def _check_s3_public_block(client, bucket_name: str) -> List[Dict]:
    try:
        resp = client.get_public_access_block(Bucket=bucket_name)
        cfg = resp.get('PublicAccessBlockConfiguration', {})
        if all([
            cfg.get('BlockPublicAcls'),
            cfg.get('IgnorePublicAcls'),
            cfg.get('BlockPublicPolicy'),
            cfg.get('RestrictPublicBuckets'),
        ]):
            return []
    except Exception:
        pass
    return [_finding(
        rule_id='S3_PUBLIC_BLOCK_DISABLED',
        severity='HIGH',
        resource=bucket_name,
        title='S3パブリックアクセスブロックが無効です',
        description='パブリックアクセスブロックが無効だと意図しない公開リスクがあります',
        fix='S3コンソールで「パブリックアクセスをすべてブロック」を有効化してください',
    )]


def _check_s3_versioning(client, bucket_name: str) -> List[Dict]:
    resp = client.get_bucket_versioning(Bucket=bucket_name)
    if resp.get('Status') != 'Enabled':
        return [_finding(
            rule_id='S3_VERSIONING_DISABLED',
            severity='MEDIUM',
            resource=bucket_name,
            title='S3バケットのバージョニングが無効です',
            description='バージョニングが無効だとオブジェクト誤削除から復元できません',
            fix='S3コンソールからバージョニングを有効化してください',
        )]
    return []


def _check_s3_encryption(client, bucket_name: str) -> List[Dict]:
    try:
        client.get_bucket_encryption(Bucket=bucket_name)
        return []
    except Exception:
        return [_finding(
            rule_id='S3_ENCRYPTION_DISABLED',
            severity='MEDIUM',
            resource=bucket_name,
            title='S3バケットのデフォルト暗号化が無効です',
            description='暗号化が無効だとデータ漏洩時のリスクが高まります',
            fix='バケットのデフォルト暗号化（SSE-S3またはSSE-KMS）を有効化してください',
        )]


def _check_s3_logging(client, bucket_name: str) -> List[Dict]:
    resp = client.get_bucket_logging(Bucket=bucket_name)
    if 'LoggingEnabled' not in resp:
        return [_finding(
            rule_id='S3_LOGGING_DISABLED',
            severity='LOW',
            resource=bucket_name,
            title='S3バケットのアクセスログが無効です',
            description='アクセスログがないと不正アクセスの追跡ができません',
            fix='サーバーアクセスログを有効化してください',
        )]
    return []


def scan_iam(profile: str) -> List[Dict]:
    session = boto3.Session(profile_name=profile)
    client = session.client('iam')
    findings = []

    summary = client.get_account_summary()['SummaryMap']

    if summary.get('AccountAccessKeysPresent', 0) > 0:
        findings.append(_finding(
            rule_id='IAM_ROOT_ACCESS_KEY',
            severity='CRITICAL',
            resource='root',
            title='rootアカウントにアクセスキーが存在します',
            description='rootアクセスキーは漏洩時のリスクが極めて高いです',
            fix='rootアクセスキーをすぐに削除してください',
        ))

    if summary.get('AccountMFAEnabled', 0) == 0:
        findings.append(_finding(
            rule_id='IAM_ROOT_MFA_DISABLED',
            severity='CRITICAL',
            resource='root',
            title='rootアカウントのMFAが無効です',
            description='MFAなしのrootアカウントはパスワード漏洩で即座に乗っ取られます',
            fix='AWSコンソールでrootアカウントのMFAデバイスを登録してください',
        ))

    try:
        client.get_account_password_policy()
    except Exception:
        findings.append(_finding(
            rule_id='IAM_PASSWORD_POLICY_MISSING',
            severity='MEDIUM',
            resource='account',
            title='IAMパスワードポリシーが未設定です',
            description='パスワードポリシーがないと弱いパスワードが許可されます',
            fix='IAMコンソールでパスワードポリシー（最小8文字・大文字小文字数字記号）を設定してください',
        ))

    return findings


def _finding(rule_id: str, severity: str, resource: str,
             title: str, description: str, fix: str) -> Dict:
    return {
        'rule_id': rule_id,
        'severity': severity,
        'resource': resource,
        'title': title,
        'description': description,
        'fix': fix,
    }

from typing import List, Dict


def get_demo_findings() -> List[Dict]:
    return [
        {
            'rule_id': 'IAM_ROOT_ACCESS_KEY',
            'severity': 'CRITICAL',
            'resource': 'root',
            'title': 'rootアカウントにアクセスキーが存在します',
            'description': 'rootアクセスキーは漏洩時のリスクが極めて高いです',
            'fix': 'rootアクセスキーを今すぐ削除してください',
        },
        {
            'rule_id': 'S3_PUBLIC_ACL',
            'severity': 'HIGH',
            'resource': 'mycompany-assets-prod',
            'title': 'S3バケットが公開ACLに設定されています',
            'description': '全インターネットからReadアクセスが許可されています',
            'fix': 'ACLをprivateに変更し、CloudFront経由でのみ配信してください',
        },
        {
            'rule_id': 'S3_PUBLIC_ACL',
            'severity': 'HIGH',
            'resource': 'mycompany-backup-2024',
            'title': 'S3バケットが公開ACLに設定されています',
            'description': 'バックアップバケットが公開されています',
            'fix': 'ACLをprivateに変更してください',
        },
        {
            'rule_id': 'S3_VERSIONING_DISABLED',
            'severity': 'MEDIUM',
            'resource': 'mycompany-uploads',
            'title': 'S3バケットのバージョニングが無効です',
            'description': 'オブジェクトの誤削除から復元できません',
            'fix': 'バージョニングを有効化してください',
        },
        {
            'rule_id': 'S3_PUBLIC_BLOCK_DISABLED',
            'severity': 'HIGH',
            'resource': 'mycompany-legacy-bucket',
            'title': 'S3パブリックアクセスブロックが無効です',
            'description': 'パブリックアクセスブロックが無効だと意図しない公開リスクがあります',
            'fix': 'S3コンソールで「パブリックアクセスをすべてブロック」を有効化してください',
        },
        {
            'rule_id': 'IAM_ROOT_MFA_DISABLED',
            'severity': 'CRITICAL',
            'resource': 'root',
            'title': 'rootアカウントのMFAが無効です',
            'description': 'MFAなしのrootアカウントはパスワード漏洩で即座に乗っ取られます',
            'fix': 'AWSコンソールでrootアカウントのMFAデバイスを登録してください',
        },
        {
            'rule_id': 'S3_ENCRYPTION_DISABLED',
            'severity': 'MEDIUM',
            'resource': 'mycompany-data-lake',
            'title': 'S3バケットのデフォルト暗号化が無効です',
            'description': '暗号化が無効だとデータ漏洩時のリスクが高まります',
            'fix': 'バケットのデフォルト暗号化（SSE-S3またはSSE-KMS）を有効化してください',
        },
        {
            'rule_id': 'IAM_PASSWORD_POLICY_MISSING',
            'severity': 'MEDIUM',
            'resource': 'account',
            'title': 'IAMパスワードポリシーが未設定です',
            'description': 'パスワードポリシーがないと弱いパスワードが許可されます',
            'fix': 'IAMコンソールでパスワードポリシーを設定してください',
        },
        {
            'rule_id': 'S3_LOGGING_DISABLED',
            'severity': 'LOW',
            'resource': 'mycompany-static',
            'title': 'S3バケットのアクセスログが無効です',
            'description': 'アクセスログがないと不正アクセスの追跡ができません',
            'fix': 'サーバーアクセスログを有効化してください',
        },
    ]

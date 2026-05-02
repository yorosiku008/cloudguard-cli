# CloudGuard JP

AWSセキュリティスキャンCLI — S3/IAM/EC2/CloudTrailの設定問題を自動検出します。

[![Tests](https://github.com/yorosiku008/cloudguard-cli/actions/workflows/test.yml/badge.svg)](https://github.com/yorosiku008/cloudguard-cli/actions)

## インストール

```bash
pip install -r requirements.txt
```

## 使い方

```bash
# デモデータで動作確認（AWS不要）
python main.py --demo

# 実環境スキャン
python main.py --profile default --services s3 iam ec2 cloudtrail

# 重要度フィルター（CRITICAL/HIGH のみ表示）
python main.py --demo --severity CRITICAL HIGH

# Markdownレポート出力
python main.py --demo --output-md

# Claude AI による修正提案を生成（ANTHROPIC_API_KEY 必要）
python main.py --demo --ai
```

## オプション

| オプション | デフォルト | 説明 |
|-----------|----------|------|
| `--profile` | `default` | AWS プロファイル名 |
| `--services` | 全サービス | スキャン対象（s3 iam ec2 cloudtrail） |
| `--severity` | 全件 | 表示する重要度フィルター |
| `--output-md` | `false` | MDレポートを出力 |
| `--demo` | `false` | デモデータで動作確認 |
| `--ai` | `false` | Claude AI による修正提案を生成 |

## 検出ルール（14ルール）

### IAM（3ルール）

| ルールID | 重要度 | 説明 |
|----------|--------|------|
| IAM_ROOT_ACCESS_KEY | CRITICAL | rootアカウントにアクセスキーが存在 |
| IAM_ROOT_MFA_DISABLED | CRITICAL | rootアカウントのMFAが無効 |
| IAM_PASSWORD_POLICY_MISSING | MEDIUM | IAMパスワードポリシーが未設定 |

### S3（5ルール）

| ルールID | 重要度 | 説明 |
|----------|--------|------|
| S3_PUBLIC_ACL | HIGH | S3バケットが公開ACLに設定 |
| S3_PUBLIC_BLOCK_DISABLED | HIGH | パブリックアクセスブロックが無効 |
| S3_VERSIONING_DISABLED | MEDIUM | S3バージョニングが無効 |
| S3_ENCRYPTION_DISABLED | MEDIUM | デフォルト暗号化が無効 |
| S3_LOGGING_DISABLED | LOW | S3アクセスログが無効 |

### EC2（4ルール）

| ルールID | 重要度 | 説明 |
|----------|--------|------|
| EC2_SG_SSH_OPEN | HIGH | SGでSSH(22)が全公開 |
| EC2_SG_RDP_OPEN | HIGH | SGでRDP(3389)が全公開 |
| EC2_SG_MySQL_OPEN | HIGH | SGでMySQL(3306)が全公開 |
| EC2_SG_PostgreSQL_OPEN | HIGH | SGでPostgreSQL(5432)が全公開 |

### CloudTrail（2ルール）

| ルールID | 重要度 | 説明 |
|----------|--------|------|
| CLOUDTRAIL_NOT_ENABLED | HIGH | CloudTrailが有効化されていない |
| CLOUDTRAIL_NOT_MULTIREGION | MEDIUM | CloudTrailがシングルリージョン設定 |

## セットアップ（AI機能を使う場合）

```bash
# Windows
set ANTHROPIC_API_KEY=sk-ant-...

# Mac/Linux
export ANTHROPIC_API_KEY=sk-ant-...
```

## テスト

```bash
pytest tests/ -v
```

## 必要なAWS権限

```json
{
  "Action": [
    "s3:GetBucketAcl", "s3:GetBucketVersioning",
    "s3:GetBucketLogging", "s3:ListAllMyBuckets",
    "s3:GetBucketEncryption", "s3:GetPublicAccessBlock",
    "iam:GetAccountSummary", "iam:GetAccountPasswordPolicy",
    "ec2:DescribeSecurityGroups",
    "cloudtrail:DescribeTrails"
  ]
}
```

---

*CloudGuard JP v0.1.0*

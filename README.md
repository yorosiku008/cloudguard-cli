# CloudGuard JP

AWSセキュリティスキャンCLI — S3/IAM設定の問題を自動検出します。

## インストール

```bash
pip install -r requirements.txt
```

## 使い方

```bash
# デモデータで動作確認（AWS不要）
python main.py --demo

# 実環境スキャン（AWSアカウント必要）
python main.py --profile default --services s3 iam

# Markdownレポート出力
python main.py --demo --output-md
```

## 検出ルール

| ルールID | 重要度 | 説明 |
|----------|--------|------|
| IAM_ROOT_ACCESS_KEY | CRITICAL | rootアカウントにアクセスキーが存在 |
| S3_PUBLIC_ACL | HIGH | S3バケットが公開ACLに設定 |
| S3_VERSIONING_DISABLED | MEDIUM | S3バージョニングが無効 |
| S3_LOGGING_DISABLED | LOW | S3アクセスログが無効 |

## テスト

```bash
pytest tests/ -v
```

## 必要なAWS権限

```json
{
  "Action": ["s3:GetBucketAcl", "s3:GetBucketVersioning",
             "s3:GetBucketLogging", "s3:ListAllMyBuckets",
             "iam:GetAccountSummary"]
}
```

---

*CloudGuard JP v0.1.0 — FinOps JP プロジェクト*

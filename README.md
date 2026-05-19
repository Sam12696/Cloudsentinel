# CloudSentinel

**AI-powered AWS cost optimization and resource monitoring tool.**

CloudSentinel scans your AWS account, detects wasteful or unused resources, and surfaces actionable savings recommendations — combining rule-based analysis with a scikit-learn machine learning anomaly detector.

---

## What It Does

- Scans **11 AWS services**: EC2, S3, RDS, Lambda, EBS, ELB, CloudFront, NAT Gateway, Elastic IP, DynamoDB, IAM
- Applies **heuristic rules** (idle instances, public buckets, unattached volumes, disabled backups, etc.)
- Runs an **Isolation Forest ML model** to detect statistically anomalous resource usage and cost patterns
- Outputs a **rich CLI table**, a **JSON report**, and a **styled HTML report**
- Estimates **monthly savings** per finding

---

## How It Works

```
AWS Account
    │
    ▼
Collectors (boto3)          ← pull raw data per service per region
    │
    ▼
Rules Engine                ← heuristic checks (idle CPU, unattached volumes, etc.)
    │
    ▼
ML Anomaly Detector         ← scikit-learn Isolation Forest flags statistical outliers
    │
    ▼
CLI + Reports               ← rich table, JSON, HTML
```

### Rule-Based Analysis
Each service has dedicated rules. Examples:
| Service | Rule |
|---------|------|
| EC2 | CPU < 5% for 14 days → idle instance |
| EBS | Volume not attached → unused, delete |
| EBS | Volume type gp2 → upgrade to gp3 (20% cheaper) |
| S3 | Public ACL → security finding |
| S3 | > 10 GB, no lifecycle policy → cost finding |
| RDS | Zero connections for 14 days → unused |
| RDS | No automated backups → reliability risk |
| Lambda | 0 invocations in 30 days → unused function |
| IAM | User without MFA → security risk |
| IAM | Access key older than 90 days → rotate |

### ML Anomaly Detection (Isolation Forest)
The ML layer uses scikit-learn's `IsolationForest` to detect resources that are statistical outliers compared to similar resources in your account:
- **EC2**: anomalous CPU + network + cost combinations
- **EBS**: anomalous I/O patterns relative to volume size
- **RDS**: anomalous CPU + connections + cost patterns
- **Cross-service**: any resource with anomalously high cost vs. peers

---

## Requirements

- Python 3.10+
- AWS credentials configured (via CLI, environment variables, or IAM role)
- AWS account with read permissions

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/Sam12696/Cloudsentinel.git
cd cloudsentinel
```

### 2. Create and activate a virtual environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -e .
```

### 4. Link your AWS Account

CloudSentinel uses the standard AWS credential chain. Choose one option:

#### Option A — AWS CLI (recommended)
```bash
# Install AWS CLI, then:
aws configure
# Enter your Access Key ID, Secret Access Key, region (e.g. us-east-1)
```

#### Option B — Environment variables
```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1
```

#### Option C — Named profile
```bash
aws configure --profile myprofile
cloudsentinel scan --profile myprofile
```

#### Option D — IAM Role (EC2 / Lambda / ECS)
If running on AWS infrastructure with an IAM role attached, no configuration is needed — credentials are automatically picked up.

#### Required IAM Permissions
Your AWS user/role needs **read-only** access. Attach the AWS managed policy:
```
ReadOnlyAccess
```
Or create a custom policy with these actions:
```json
{
  "Effect": "Allow",
  "Action": [
    "ec2:Describe*",
    "s3:List*", "s3:GetBucket*",
    "rds:Describe*",
    "lambda:List*", "lambda:GetFunction*",
    "elasticloadbalancing:Describe*",
    "cloudwatch:GetMetricStatistics",
    "iam:List*", "iam:Get*",
    "cloudfront:List*",
    "dynamodb:List*", "dynamodb:Describe*",
    "sts:GetCallerIdentity"
  ],
  "Resource": "*"
}
```

---

## Running CloudSentinel

### Basic scan (all services, default region)
```bash
cloudsentinel scan
```

### Scan a specific region
```bash
cloudsentinel scan --region us-east-1
```

### Scan multiple regions
```bash
cloudsentinel scan --region us-east-1 --regions eu-west-1 --regions ap-southeast-1
```

### Scan specific services only
```bash
cloudsentinel scan --services ec2 --services ebs --services s3
```

### Save reports
```bash
cloudsentinel scan --output-json report.json --output-html report.html
```
Then open `report.html` in your browser for a formatted view.

### Disable ML anomaly detection (rules only)
```bash
cloudsentinel scan --no-ml
```

### Adjust thresholds
```bash
# Flag instances with CPU below 10% (default: 5%)
cloudsentinel scan --cpu-threshold 10.0

# Flag resources unused for 60+ days (default: 90)
cloudsentinel scan --days-threshold 60
```

### Full example
```bash
cloudsentinel scan \
  --profile myprofile \
  --region us-east-1 \
  --regions eu-west-1 \
  --services ec2 ebs rds s3 lambda \
  --cpu-threshold 10 \
  --output-json report.json \
  --output-html report.html
```

---

## Example Output

```
+---------------------------- CloudSentinel Scan -----------------------------+
| Regions : us-east-1                                                         |
| Services: s3, ec2, rds, lambda, ebs, elb ...                                |
| ML      : enabled (Isolation Forest)                                        |
+-----------------------------------------------------------------------------+

+-----------+----------+--------------------+-----------+----------------------+------------+
| Severity  | Service  | Resource           | Region    | Finding              | Savings/mo |
+-----------+----------+--------------------+-----------+----------------------+------------+
| HIGH      | EC2      | prod-old-server    | us-east-1 | Idle EC2 instance    |      $63   |
| HIGH      | EBS      | vol-0abc123        | us-east-1 | Unattached EBS vol.. |      $80   |
| MEDIUM    | RDS      | dev-db-01          | us-east-1 | No connections 14d   |     $125   |
| MEDIUM    | Lambda   | old-cleanup-func   | us-east-1 | Zero invocations..   |       $0   |
| LOW       | EBS      | data-vol-02        | us-east-1 | Upgrade gp2 to gp3   |       $8   |
+-----------+----------+--------------------+-----------+----------------------+------------+
Est. Monthly Savings: $276.00
```

---

## Project Structure

```
cloudsentinel/
├── cloudsentinel/
│   ├── cli.py                  # CLI entry point (click + rich)
│   ├── config.py               # Configuration & AWS session
│   ├── models.py               # Finding, ScanResult data models
│   ├── collectors/             # One collector per AWS service
│   │   ├── ec2.py
│   │   ├── s3.py
│   │   ├── rds.py
│   │   └── ...
│   └── analyzers/
│       ├── rules.py            # Heuristic rule engine
│       └── ml.py               # Isolation Forest anomaly detector
├── requirements.txt
├── pyproject.toml
└── README.md
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| AWS data collection | `boto3` |
| ML anomaly detection | `scikit-learn` (Isolation Forest) |
| Data processing | `pandas`, `numpy` |
| CLI | `click` |
| Terminal output | `rich` |
| HTML reports | `jinja2` |

---

## License

MIT

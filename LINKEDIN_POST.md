# LinkedIn Post

---

I built an open-source tool that scans your AWS account and tells you exactly where you're wasting money — using Python and machine learning.

**CloudSentinel** — AI-powered AWS cost optimization 🔍

Most teams overspend on cloud without realizing it. Stopped EC2 instances still charging for storage. Unattached EBS volumes sitting idle. S3 buckets with no lifecycle policy quietly accumulating costs. RDS databases with zero connections running 24/7.

So I built a CLI tool that catches all of this automatically.

---

**How it works:**

It combines two layers of intelligence:

**1. Rules Engine**
Heuristic checks across 11 AWS services — idle EC2 instances (CPU < 5% for 14 days), unattached EBS volumes, public S3 buckets, RDS with no connections, Lambda functions with zero invocations, IAM users without MFA, access keys older than 90 days, and more.

**2. Machine Learning — Isolation Forest**
This is where it gets interesting. I used scikit-learn's Isolation Forest algorithm — an unsupervised ML model — to detect resources that are statistical outliers compared to similar resources in your account.

The model learns what "normal" looks like across your EC2 instances (CPU, network, cost), EBS volumes (I/O patterns, size), and RDS databases (connections, CPU, storage). Anything that deviates significantly from the norm gets flagged — even if it doesn't break any specific rule.

No labeled training data needed. No external AI API. Pure Python ML running locally against your own AWS metrics.

---

**Run it in 3 commands:**

```bash
git clone https://github.com/YOUR_USERNAME/cloudsentinel
cd cloudsentinel && pip install -e .
cloudsentinel scan --region us-east-1 --output-html report.html
```

Open report.html and see exactly what's costing you money.

---

**Tech stack:**
- boto3 — AWS data collection
- scikit-learn — Isolation Forest anomaly detection
- pandas + numpy — feature engineering
- click + rich — CLI and terminal output

**GitHub:** https://github.com/Sam12696/Cloudsentinel

If you're running anything on AWS, give it a scan. Happy to answer questions in the comments.

#AWS #CloudCost #MachineLearning #Python #OpenSource #DevOps #CloudOptimization #boto3 #sklearn

---

# Short description for sharing the GitHub URL separately

> Built CloudSentinel — an open-source AWS cost optimization tool that uses scikit-learn's Isolation Forest ML model to detect anomalous and wasteful cloud resources. It scans EC2, S3, RDS, Lambda, EBS and more, combining heuristic rules with unsupervised machine learning to surface savings you didn't know existed. No external AI API — pure Python, runs locally against your own AWS account.
> 🔗 GitHub: https://github.com/Sam12696/Cloudsentinel
> #AWS #Python #MachineLearning #OpenSource

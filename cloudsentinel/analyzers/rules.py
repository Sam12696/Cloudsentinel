from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from cloudsentinel.models import Category, Finding, Severity

if TYPE_CHECKING:
    from cloudsentinel.config import Config

logger = logging.getLogger(__name__)


class RulesEngine:
    def __init__(self, config: "Config") -> None:
        self.config = config

    # ------------------------------------------------------------------ EC2
    def analyze_ec2(self, resources: list[dict]) -> list[Finding]:
        findings = []
        for r in resources:
            state = r.get("state", "")
            iid = r["instance_id"]
            name = r["instance_name"]
            region = r["region"]
            cpu = r.get("avg_cpu_14d")
            monthly_cost = r.get("monthly_cost_usd", 0)
            itype = r.get("instance_type", "unknown")

            if state == "stopped":
                findings.append(Finding(
                    service="EC2", resource_id=iid, resource_name=name, region=region,
                    severity=Severity.HIGH, category=Category.UNUSED,
                    title=f"Stopped EC2 instance: {name}",
                    description=f"Instance {name} ({iid}) is stopped but still accruing EBS storage costs.",
                    recommendation="Terminate the instance if unused, or start it if it should be running.",
                    estimated_monthly_savings=monthly_cost * 0.1,
                    metadata={"state": state, "instance_type": itype},
                    tags=r.get("tags", {}),
                ))
            elif state == "running" and cpu is not None:
                net_in = r.get("avg_network_in_14d") or 0
                net_out = r.get("avg_network_out_14d") or 0
                net_mb = (net_in + net_out) / (1024 * 1024)

                if cpu < self.config.cpu_threshold and net_mb < self.config.network_threshold:
                    findings.append(Finding(
                        service="EC2", resource_id=iid, resource_name=name, region=region,
                        severity=Severity.HIGH, category=Category.UNUSED,
                        title=f"Idle EC2 instance: {name}",
                        description=(
                            f"CPU {cpu:.1f}% avg, network {net_mb:.2f} MB avg over 14 days."
                        ),
                        recommendation="Terminate or stop the instance; it is not serving workloads.",
                        estimated_monthly_savings=monthly_cost * 0.9,
                        metadata={"avg_cpu": cpu, "avg_network_mb": net_mb, "instance_type": itype},
                        tags=r.get("tags", {}),
                    ))
                elif cpu < self.config.cpu_threshold:
                    findings.append(Finding(
                        service="EC2", resource_id=iid, resource_name=name, region=region,
                        severity=Severity.MEDIUM, category=Category.RIGHTSIZING,
                        title=f"Underutilized EC2 instance: {name}",
                        description=f"CPU {cpu:.1f}% avg over 14 days on {itype}.",
                        recommendation=f"Downsize from {itype} to a smaller instance type.",
                        estimated_monthly_savings=monthly_cost * 0.4,
                        metadata={"avg_cpu": cpu, "instance_type": itype},
                        tags=r.get("tags", {}),
                    ))
        return findings

    # ------------------------------------------------------------------ S3
    def analyze_s3(self, resources: list[dict]) -> list[Finding]:
        findings = []
        for r in resources:
            name = r["bucket_name"]
            region = r["region"]
            size_bytes = r.get("size_bytes", 0) or 0
            object_count = r.get("object_count", 0) or 0
            is_public = r.get("is_public", False)
            has_lifecycle = r.get("has_lifecycle_policy", False)
            storage_classes = r.get("storage_classes", {})

            if is_public:
                findings.append(Finding(
                    service="S3", resource_id=name, resource_name=name, region=region,
                    severity=Severity.CRITICAL, category=Category.SECURITY,
                    title=f"Public S3 bucket: {name}",
                    description=f"Bucket {name} grants public read access via ACL.",
                    recommendation="Enable S3 Block Public Access unless hosting a public website.",
                    estimated_monthly_savings=0.0,
                    metadata={"size_bytes": size_bytes, "object_count": object_count},
                    tags=r.get("tags", {}),
                ))

            size_gb = size_bytes / (1024 ** 3)
            if size_gb > 10 and not has_lifecycle:
                monthly_cost = size_gb * 0.023
                findings.append(Finding(
                    service="S3", resource_id=name, resource_name=name, region=region,
                    severity=Severity.MEDIUM, category=Category.COST,
                    title=f"S3 bucket missing lifecycle policy: {name}",
                    description=f"Bucket contains {size_gb:.1f} GB but has no lifecycle policy.",
                    recommendation="Add a lifecycle rule to transition old objects to Glacier or delete expired data.",
                    estimated_monthly_savings=monthly_cost * 0.3,
                    metadata={"size_gb": size_gb, "object_count": object_count},
                    tags=r.get("tags", {}),
                ))

            standard_objects = storage_classes.get("STANDARD", 0)
            if object_count > 0 and standard_objects / max(object_count, 1) > 0.8 and size_gb > 100:
                monthly_cost = size_gb * 0.023
                findings.append(Finding(
                    service="S3", resource_id=name, resource_name=name, region=region,
                    severity=Severity.LOW, category=Category.COST,
                    title=f"Large S3 bucket using Standard storage: {name}",
                    description=f"{size_gb:.0f} GB in Standard storage class.",
                    recommendation="Enable S3 Intelligent-Tiering or move infrequently accessed data to Standard-IA.",
                    estimated_monthly_savings=monthly_cost * 0.25,
                    metadata={"size_gb": size_gb},
                    tags=r.get("tags", {}),
                ))

            if object_count == 0:
                creation = r.get("creation_date")
                if creation:
                    from datetime import datetime, timezone
                    if creation.tzinfo is None:
                        creation = creation.replace(tzinfo=timezone.utc)
                    age_days = (datetime.now(timezone.utc) - creation).days
                    if age_days > 30:
                        findings.append(Finding(
                            service="S3", resource_id=name, resource_name=name, region=region,
                            severity=Severity.LOW, category=Category.UNUSED,
                            title=f"Empty S3 bucket: {name}",
                            description=f"Bucket has been empty for {age_days} days.",
                            recommendation="Delete the bucket if it is no longer needed.",
                            estimated_monthly_savings=0.0,
                            metadata={"age_days": age_days},
                            tags=r.get("tags", {}),
                        ))
        return findings

    # ------------------------------------------------------------------ EBS
    def analyze_ebs(self, resources: list[dict]) -> list[Finding]:
        findings = []
        for r in resources:
            vid = r["volume_id"]
            name = r["volume_name"]
            region = r["region"]
            monthly_cost = r.get("monthly_cost_usd", 0)

            if vid.startswith("snap:"):
                days_old = r.get("snapshot_days_old", 0) or 0
                if days_old > self.config.days_threshold:
                    findings.append(Finding(
                        service="EBS", resource_id=vid.replace("snap:", ""),
                        resource_name=name, region=region,
                        severity=Severity.LOW, category=Category.COST,
                        title=f"Old EBS snapshot: {name}",
                        description=f"Snapshot is {days_old:.0f} days old.",
                        recommendation="Delete snapshots older than your retention policy.",
                        estimated_monthly_savings=monthly_cost,
                        metadata={"days_old": days_old, "size_gb": r.get("size_gb")},
                    ))
                continue

            if not r.get("is_attached"):
                findings.append(Finding(
                    service="EBS", resource_id=vid, resource_name=name, region=region,
                    severity=Severity.HIGH, category=Category.UNUSED,
                    title=f"Unattached EBS volume: {name}",
                    description=f"Volume {vid} is not attached to any instance.",
                    recommendation="Snapshot and delete the volume, or attach it to an instance.",
                    estimated_monthly_savings=monthly_cost,
                    metadata={"size_gb": r.get("size_gb"), "volume_type": r.get("volume_type")},
                    tags=r.get("tags", {}),
                ))
            elif r.get("volume_type") == "gp2":
                size_gb = r.get("size_gb", 0)
                gp3_cost = size_gb * 0.08
                savings = monthly_cost - gp3_cost
                if savings > 0:
                    findings.append(Finding(
                        service="EBS", resource_id=vid, resource_name=name, region=region,
                        severity=Severity.LOW, category=Category.COST,
                        title=f"Upgrade gp2 to gp3: {name}",
                        description=(
                            f"Volume uses gp2 (${monthly_cost:.2f}/mo). "
                            "gp3 delivers 20% better baseline throughput at lower cost."
                        ),
                        recommendation="Modify volume type from gp2 to gp3.",
                        estimated_monthly_savings=savings,
                        metadata={"volume_type": "gp2", "size_gb": size_gb},
                        tags=r.get("tags", {}),
                    ))
        return findings

    # ------------------------------------------------------------------ RDS
    def analyze_rds(self, resources: list[dict]) -> list[Finding]:
        findings = []
        for r in resources:
            dbid = r["db_instance_id"]
            region = r["region"]
            monthly_cost = r.get("monthly_cost_usd", 0)
            connections = r.get("avg_connections_14d")
            cpu = r.get("avg_cpu_14d")
            multi_az = r.get("multi_az", False)
            backup_days = r.get("backup_retention_days", 0)
            iclass = r.get("instance_class", "unknown")

            if connections is not None and connections < 1 and r.get("status") == "available":
                findings.append(Finding(
                    service="RDS", resource_id=dbid, resource_name=dbid, region=region,
                    severity=Severity.HIGH, category=Category.UNUSED,
                    title=f"RDS instance with no connections: {dbid}",
                    description=f"Average connections over 14 days: {connections:.2f}.",
                    recommendation="Snapshot and delete the instance if it is not needed.",
                    estimated_monthly_savings=monthly_cost * 0.9,
                    metadata={"avg_connections": connections, "instance_class": iclass},
                    tags=r.get("tags", {}),
                ))
            elif cpu is not None and cpu < self.config.cpu_threshold:
                findings.append(Finding(
                    service="RDS", resource_id=dbid, resource_name=dbid, region=region,
                    severity=Severity.MEDIUM, category=Category.RIGHTSIZING,
                    title=f"Underutilized RDS instance: {dbid}",
                    description=f"CPU {cpu:.1f}% avg over 14 days on {iclass}.",
                    recommendation="Downsize to a smaller instance class.",
                    estimated_monthly_savings=monthly_cost * 0.35,
                    metadata={"avg_cpu": cpu, "instance_class": iclass},
                    tags=r.get("tags", {}),
                ))

            if not multi_az:
                findings.append(Finding(
                    service="RDS", resource_id=dbid, resource_name=dbid, region=region,
                    severity=Severity.MEDIUM, category=Category.RELIABILITY,
                    title=f"Single-AZ RDS instance: {dbid}",
                    description="Instance is not Multi-AZ; a single-AZ failure will cause downtime.",
                    recommendation="Enable Multi-AZ for production databases.",
                    estimated_monthly_savings=0.0,
                    metadata={"multi_az": multi_az},
                    tags=r.get("tags", {}),
                ))

            if backup_days == 0:
                findings.append(Finding(
                    service="RDS", resource_id=dbid, resource_name=dbid, region=region,
                    severity=Severity.HIGH, category=Category.RELIABILITY,
                    title=f"RDS automated backups disabled: {dbid}",
                    description="BackupRetentionPeriod is 0; automated backups are off.",
                    recommendation="Enable automated backups with at least 7 days retention.",
                    estimated_monthly_savings=0.0,
                    metadata={"backup_retention_days": backup_days},
                    tags=r.get("tags", {}),
                ))
        return findings

    # ------------------------------------------------------------------ Lambda
    def analyze_lambda(self, resources: list[dict]) -> list[Finding]:
        findings = []
        for r in resources:
            fname = r["function_name"]
            region = r["region"]
            invocations = r.get("invocations_30d") or 0
            errors = r.get("errors_30d") or 0
            memory_mb = r.get("memory_mb", 128)
            monthly_cost = r.get("estimated_monthly_cost_usd", 0)

            if invocations == 0:
                findings.append(Finding(
                    service="Lambda", resource_id=fname, resource_name=fname, region=region,
                    severity=Severity.MEDIUM, category=Category.UNUSED,
                    title=f"Lambda function with zero invocations: {fname}",
                    description="Function had no invocations in the last 30 days.",
                    recommendation="Delete the function or verify it has an active event source.",
                    estimated_monthly_savings=monthly_cost,
                    metadata={"invocations_30d": invocations, "memory_mb": memory_mb},
                    tags=r.get("tags", {}),
                ))
            elif invocations > 0 and errors / max(invocations, 1) > 0.1:
                findings.append(Finding(
                    service="Lambda", resource_id=fname, resource_name=fname, region=region,
                    severity=Severity.HIGH, category=Category.RELIABILITY,
                    title=f"High Lambda error rate: {fname}",
                    description=f"Error rate {errors/invocations*100:.1f}% over 30 days.",
                    recommendation="Investigate function errors in CloudWatch Logs.",
                    estimated_monthly_savings=0.0,
                    metadata={"invocations_30d": invocations, "errors_30d": errors},
                    tags=r.get("tags", {}),
                ))

            if memory_mb > 512 and invocations > 0:
                avg_duration = r.get("avg_duration_ms_30d") or 0
                if avg_duration < 100:
                    findings.append(Finding(
                        service="Lambda", resource_id=fname, resource_name=fname, region=region,
                        severity=Severity.LOW, category=Category.RIGHTSIZING,
                        title=f"Oversized Lambda memory: {fname}",
                        description=f"Function allocated {memory_mb} MB but avg duration is {avg_duration:.0f} ms.",
                        recommendation="Reduce memory allocation to lower cost; use Lambda Power Tuning.",
                        estimated_monthly_savings=monthly_cost * 0.3,
                        metadata={"memory_mb": memory_mb, "avg_duration_ms": avg_duration},
                        tags=r.get("tags", {}),
                    ))
        return findings

    # ------------------------------------------------------------------ ELB
    def analyze_elb(self, resources: list[dict]) -> list[Finding]:
        findings = []
        for r in resources:
            arn = r["lb_arn"]
            name = r["lb_name"]
            region = r["region"]
            healthy = r.get("healthy_targets", 0)
            total = r.get("total_targets", 0)
            requests = r.get("avg_requests_14d") or 0
            monthly_cost = r.get("monthly_cost_usd", 0)

            if total == 0:
                findings.append(Finding(
                    service="ELB", resource_id=arn, resource_name=name, region=region,
                    severity=Severity.HIGH, category=Category.UNUSED,
                    title=f"Load balancer with no targets: {name}",
                    description="No target groups registered to this load balancer.",
                    recommendation="Delete the load balancer if it is not actively routing traffic.",
                    estimated_monthly_savings=monthly_cost,
                    metadata={"lb_type": r.get("lb_type")},
                    tags=r.get("tags", {}),
                ))
            elif requests < 10 and total > 0:
                findings.append(Finding(
                    service="ELB", resource_id=arn, resource_name=name, region=region,
                    severity=Severity.MEDIUM, category=Category.UNUSED,
                    title=f"Load balancer with very low traffic: {name}",
                    description=f"Avg {requests:.0f} requests/day over 14 days.",
                    recommendation="Verify this load balancer is still needed; consider consolidating.",
                    estimated_monthly_savings=monthly_cost * 0.5,
                    metadata={"avg_requests_14d": requests, "healthy_targets": healthy},
                    tags=r.get("tags", {}),
                ))
        return findings

    # ------------------------------------------------------------------ NAT Gateway
    def analyze_nat_gateway(self, resources: list[dict]) -> list[Finding]:
        findings = []
        for r in resources:
            gw_id = r["gateway_id"]
            region = r["region"]
            total_gb = r.get("total_data_gb_30d", 0) or 0
            monthly_cost = r.get("monthly_cost_usd", 0)

            if total_gb < 1:
                findings.append(Finding(
                    service="NAT Gateway", resource_id=gw_id, resource_name=gw_id, region=region,
                    severity=Severity.HIGH, category=Category.UNUSED,
                    title=f"Idle NAT Gateway: {gw_id}",
                    description=f"Only {total_gb:.2f} GB processed in 30 days.",
                    recommendation="Delete the NAT Gateway if no private subnets require internet access.",
                    estimated_monthly_savings=monthly_cost,
                    metadata={"total_data_gb_30d": total_gb},
                    tags=r.get("tags", {}),
                ))
        return findings

    # ------------------------------------------------------------------ Elastic IP
    def analyze_elastic_ip(self, resources: list[dict]) -> list[Finding]:
        findings = []
        for r in resources:
            alloc_id = r["allocation_id"]
            name = r["eip_name"]
            region = r["region"]
            is_attached = r.get("is_attached", False)
            monthly_cost = r.get("monthly_cost_usd", 0)

            if not is_attached:
                findings.append(Finding(
                    service="Elastic IP", resource_id=alloc_id, resource_name=name, region=region,
                    severity=Severity.MEDIUM, category=Category.UNUSED,
                    title=f"Unattached Elastic IP: {r.get('public_ip', alloc_id)}",
                    description="Elastic IP is allocated but not associated with any resource.",
                    recommendation="Release the Elastic IP to avoid the $3.65/mo idle charge.",
                    estimated_monthly_savings=monthly_cost,
                    metadata={"public_ip": r.get("public_ip")},
                    tags=r.get("tags", {}),
                ))
        return findings

    # ------------------------------------------------------------------ IAM
    def analyze_iam(self, resources: list[dict]) -> list[Finding]:
        findings = []
        for r in resources:
            rtype = r.get("resource_type", "iam_user")
            name = r["user_name"]
            arn = r["user_arn"]
            days_since = r.get("days_since_login", 0) or 0

            # Skip AWS-managed service-linked roles — not user-controlled
            if rtype == "iam_role" and ("aws-service-role" in arn or name.startswith("AWSServiceRole")):
                continue

            if rtype == "iam_user":
                if not r.get("mfa_enabled"):
                    findings.append(Finding(
                        service="IAM", resource_id=arn, resource_name=name, region="global",
                        severity=Severity.HIGH, category=Category.SECURITY,
                        title=f"IAM user without MFA: {name}",
                        description=f"User {name} has console access but no MFA device.",
                        recommendation="Enable MFA for all IAM users with console access.",
                        estimated_monthly_savings=0.0,
                        metadata={"user_name": name},
                    ))

                if days_since > self.config.days_threshold:
                    findings.append(Finding(
                        service="IAM", resource_id=arn, resource_name=name, region="global",
                        severity=Severity.MEDIUM, category=Category.SECURITY,
                        title=f"Inactive IAM user: {name}",
                        description=f"User has not logged in for {days_since:.0f} days.",
                        recommendation="Disable or delete inactive IAM users.",
                        estimated_monthly_savings=0.0,
                        metadata={"days_since_login": days_since},
                    ))

                for key in r.get("access_keys", []):
                    if key.get("status") == "Active" and key.get("days_old", 0) > 90:
                        findings.append(Finding(
                            service="IAM", resource_id=key["key_id"], resource_name=name,
                            region="global",
                            severity=Severity.MEDIUM, category=Category.SECURITY,
                            title=f"Old IAM access key: {name}",
                            description=f"Access key {key['key_id']} is {key['days_old']:.0f} days old.",
                            recommendation="Rotate access keys every 90 days per security best practices.",
                            estimated_monthly_savings=0.0,
                            metadata={"key_id": key["key_id"], "days_old": key["days_old"]},
                        ))

            elif rtype == "iam_role":
                if days_since > 365:
                    findings.append(Finding(
                        service="IAM", resource_id=arn, resource_name=name, region="global",
                        severity=Severity.LOW, category=Category.SECURITY,
                        title=f"Unused IAM role: {name}",
                        description=f"Role has not been used for {days_since:.0f} days.",
                        recommendation="Delete unused IAM roles to reduce the attack surface.",
                        estimated_monthly_savings=0.0,
                        metadata={"days_since_last_used": days_since},
                    ))
        return findings

    # ------------------------------------------------------------------ DynamoDB / CloudFront (pass-through stubs)
    def analyze_dynamodb(self, resources: list[dict]) -> list[Finding]:
        return []

    def analyze_cloudfront(self, resources: list[dict]) -> list[Finding]:
        return []

    # ------------------------------------------------------------------ dispatch
    def analyze(self, service: str, resources: list[dict]) -> list[Finding]:
        method = getattr(self, f"analyze_{service}", None)
        if method is None:
            return []
        try:
            return method(resources)
        except Exception as exc:
            logger.warning("RulesEngine.analyze_%s failed: %s", service, exc)
            return []

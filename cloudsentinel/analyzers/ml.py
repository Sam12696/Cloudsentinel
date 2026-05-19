from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from cloudsentinel.models import Category, Finding, Severity

if TYPE_CHECKING:
    from cloudsentinel.config import Config

logger = logging.getLogger(__name__)

MIN_SAMPLES = 5
CONTAMINATION = 0.1  # fraction of outliers expected


class AnomalyDetector:
    """Scikit-learn Isolation Forest anomaly detector for AWS resources."""

    def __init__(self, config: "Config") -> None:
        self.config = config

    def _fit_predict(self, df: pd.DataFrame, feature_cols: list[str]) -> np.ndarray:
        """Return -1 for anomalies, +1 for normal rows. Needs MIN_SAMPLES rows."""
        X = df[feature_cols].fillna(0).to_numpy(dtype=float)
        if len(X) < MIN_SAMPLES:
            return np.ones(len(X), dtype=int)
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        model = IsolationForest(contamination=CONTAMINATION, random_state=42, n_jobs=-1)
        return model.fit_predict(X_scaled)

    # ------------------------------------------------------------------ EC2
    def detect_ec2_anomalies(self, resources: list[dict]) -> list[Finding]:
        running = [
            r for r in resources
            if r.get("state") == "running" and r.get("avg_cpu_14d") is not None
        ]
        if len(running) < MIN_SAMPLES:
            return []

        df = pd.DataFrame(running)
        features = ["avg_cpu_14d", "avg_network_in_14d", "avg_network_out_14d", "monthly_cost_usd"]
        labels = self._fit_predict(df, features)

        findings = []
        for row, label in zip(running, labels):
            if label != -1:
                continue
            cpu = row.get("avg_cpu_14d", 0) or 0
            cost = row.get("monthly_cost_usd", 0) or 0
            findings.append(Finding(
                service="EC2",
                resource_id=row["instance_id"],
                resource_name=row["instance_name"],
                region=row["region"],
                severity=Severity.MEDIUM,
                category=Category.COST,
                title=f"[ML] Anomalous EC2 resource pattern: {row['instance_name']}",
                description=(
                    f"Isolation Forest flagged this instance as an outlier. "
                    f"CPU {cpu:.1f}%, ${cost:.0f}/mo."
                ),
                recommendation="Review usage patterns; consider rightsizing or termination.",
                estimated_monthly_savings=cost * 0.3,
                metadata={"avg_cpu": cpu, "monthly_cost": cost, "detector": "IsolationForest"},
                tags=row.get("tags", {}),
            ))
        return findings

    # ------------------------------------------------------------------ EBS
    def detect_ebs_anomalies(self, resources: list[dict]) -> list[Finding]:
        volumes = [
            r for r in resources
            if not r["volume_id"].startswith("snap:") and r.get("is_attached")
        ]
        if len(volumes) < MIN_SAMPLES:
            return []

        df = pd.DataFrame(volumes)
        features = ["size_gb", "avg_read_ops_14d", "avg_write_ops_14d", "monthly_cost_usd"]
        labels = self._fit_predict(df, features)

        findings = []
        for row, label in zip(volumes, labels):
            if label != -1:
                continue
            cost = row.get("monthly_cost_usd", 0) or 0
            findings.append(Finding(
                service="EBS",
                resource_id=row["volume_id"],
                resource_name=row["volume_name"],
                region=row["region"],
                severity=Severity.MEDIUM,
                category=Category.COST,
                title=f"[ML] Anomalous EBS I/O pattern: {row['volume_name']}",
                description=(
                    f"Isolation Forest flagged unusual I/O for {row['volume_id']}. "
                    f"Size {row.get('size_gb')} GB, ${cost:.0f}/mo."
                ),
                recommendation="Review I/O vs size; consider changing volume type or resizing.",
                estimated_monthly_savings=cost * 0.2,
                metadata={"size_gb": row.get("size_gb"), "monthly_cost": cost, "detector": "IsolationForest"},
                tags=row.get("tags", {}),
            ))
        return findings

    # ------------------------------------------------------------------ RDS
    def detect_rds_anomalies(self, resources: list[dict]) -> list[Finding]:
        available = [r for r in resources if r.get("status") == "available"]
        if len(available) < MIN_SAMPLES:
            return []

        df = pd.DataFrame(available)
        features = ["avg_cpu_14d", "avg_connections_14d", "storage_gb", "monthly_cost_usd"]
        labels = self._fit_predict(df, features)

        findings = []
        for row, label in zip(available, labels):
            if label != -1:
                continue
            cost = row.get("monthly_cost_usd", 0) or 0
            findings.append(Finding(
                service="RDS",
                resource_id=row["db_instance_id"],
                resource_name=row["db_instance_id"],
                region=row["region"],
                severity=Severity.MEDIUM,
                category=Category.COST,
                title=f"[ML] Anomalous RDS usage: {row['db_instance_id']}",
                description=(
                    f"Unusual combination of CPU, connections, and cost detected. "
                    f"${cost:.0f}/mo."
                ),
                recommendation="Investigate instance sizing and connection patterns.",
                estimated_monthly_savings=cost * 0.25,
                metadata={"monthly_cost": cost, "detector": "IsolationForest"},
                tags=row.get("tags", {}),
            ))
        return findings

    # ------------------------------------------------------------------ Cross-service cost anomaly
    def detect_cost_anomalies(self, all_resources: dict[str, list[dict]]) -> list[Finding]:
        """Flag resources with anomalously high cost relative to other resources of the same type."""
        cost_field_map: dict[str, tuple[str, str, str]] = {
            "ec2": ("instance_id", "instance_name", "monthly_cost_usd"),
            "ebs": ("volume_id", "volume_name", "monthly_cost_usd"),
            "rds": ("db_instance_id", "db_instance_id", "monthly_cost_usd"),
            "lambda": ("function_name", "function_name", "estimated_monthly_cost_usd"),
            "elb": ("lb_arn", "lb_name", "monthly_cost_usd"),
            "nat_gateway": ("gateway_id", "gateway_id", "monthly_cost_usd"),
        }

        records: list[dict] = []
        for service, resources in all_resources.items():
            mapping = cost_field_map.get(service)
            if not mapping:
                continue
            id_f, name_f, cost_f = mapping
            for r in resources:
                cost = r.get(cost_f) or 0
                if cost > 0:
                    records.append({
                        "service": service,
                        "resource_id": r.get(id_f, ""),
                        "resource_name": r.get(name_f, ""),
                        "region": r.get("region", ""),
                        "monthly_cost_usd": cost,
                    })

        if len(records) < MIN_SAMPLES:
            return []

        df = pd.DataFrame(records)
        labels = self._fit_predict(df, ["monthly_cost_usd"])

        findings = []
        for row, label in zip(records, labels):
            if label != -1:
                continue
            cost = row["monthly_cost_usd"]
            if cost < 50:
                continue
            findings.append(Finding(
                service=row["service"].upper(),
                resource_id=row["resource_id"],
                resource_name=row["resource_name"],
                region=row["region"],
                severity=Severity.HIGH,
                category=Category.COST,
                title=f"[ML] High-cost outlier: {row['resource_name']}",
                description=(
                    f"{row['service'].upper()} resource costs ${cost:.0f}/mo — "
                    "significantly higher than similar resources."
                ),
                recommendation="Review for rightsizing, Reserved Instance coverage, or elimination.",
                estimated_monthly_savings=cost * 0.3,
                metadata={"monthly_cost": cost, "detector": "IsolationForest"},
            ))
        return findings

    # ------------------------------------------------------------------ dispatch
    def detect(self, service: str, resources: list[dict]) -> list[Finding]:
        method_map = {
            "ec2": self.detect_ec2_anomalies,
            "ebs": self.detect_ebs_anomalies,
            "rds": self.detect_rds_anomalies,
        }
        method = method_map.get(service)
        if method is None:
            return []
        try:
            return method(resources)
        except Exception as exc:
            logger.warning("AnomalyDetector.detect_%s failed: %s", service, exc)
            return []

from __future__ import annotations

import logging
from datetime import timedelta

from .base import BaseCollector

logger = logging.getLogger(__name__)

RDS_PRICING: dict[str, float] = {
    "db.t3.micro": 0.017, "db.t3.small": 0.034, "db.t3.medium": 0.068,
    "db.t3.large": 0.136, "db.t3.xlarge": 0.272, "db.t3.2xlarge": 0.544,
    "db.m5.large": 0.171, "db.m5.xlarge": 0.342, "db.m5.2xlarge": 0.684,
    "db.m5.4xlarge": 1.368, "db.m6g.large": 0.162, "db.m6g.xlarge": 0.325,
    "db.r5.large": 0.24, "db.r5.xlarge": 0.48, "db.r5.2xlarge": 0.96,
    "db.r6g.large": 0.228, "db.r6g.xlarge": 0.456,
}


class RDSCollector(BaseCollector):
    name = "rds"

    def collect(self, region: str) -> list[dict]:
        rds = self.client("rds", region)
        cw = self.client("cloudwatch", region)
        instances = []

        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                dbid = db["DBInstanceIdentifier"]
                status = db["DBInstanceStatus"]
                engine = db.get("Engine", "unknown")
                iclass = db.get("DBInstanceClass", "unknown")
                storage_gb = db.get("AllocatedStorage", 0)
                multi_az = db.get("MultiAZ", False)
                backup_retention = db.get("BackupRetentionPeriod", 0)
                tags = {t["Key"]: t["Value"] for t in db.get("TagList", [])}

                avg_connections = self._get_avg_metric(cw, dbid, "DatabaseConnections", 14) if status == "available" else None
                avg_cpu = self._get_avg_metric(cw, dbid, "CPUUtilization", 14) if status == "available" else None
                avg_freeable_mem = self._get_avg_metric(cw, dbid, "FreeableMemory", 14) if status == "available" else None
                avg_iops = self._get_avg_metric(cw, dbid, "ReadIOPS", 14)
                write_iops = self._get_avg_metric(cw, dbid, "WriteIOPS", 14)

                hourly_cost = RDS_PRICING.get(iclass, 0.2)
                storage_cost = storage_gb * 0.115 / 30 / 24  # gp2 $/GB/month to hourly

                instances.append({
                    "db_instance_id": dbid,
                    "engine": engine,
                    "instance_class": iclass,
                    "status": status,
                    "region": region,
                    "storage_gb": storage_gb,
                    "multi_az": multi_az,
                    "backup_retention_days": backup_retention,
                    "avg_connections_14d": avg_connections,
                    "avg_cpu_14d": avg_cpu,
                    "avg_freeable_memory_14d": avg_freeable_mem,
                    "avg_read_iops_14d": avg_iops,
                    "avg_write_iops_14d": write_iops,
                    "hourly_cost_usd": hourly_cost + storage_cost,
                    "monthly_cost_usd": (hourly_cost + storage_cost) * 730,
                    "tags": tags,
                    "endpoint": db.get("Endpoint", {}).get("Address", ""),
                })

        return instances

    def _get_avg_metric(self, cw, db_id: str, metric: str, days: int) -> float | None:
        try:
            end = self.utcnow()
            start = end - timedelta(days=days)
            resp = cw.get_metric_statistics(
                Namespace="AWS/RDS",
                MetricName=metric,
                Dimensions=[{"Name": "DBInstanceIdentifier", "Value": db_id}],
                StartTime=start,
                EndTime=end,
                Period=86400,
                Statistics=["Average"],
            )
            points = resp.get("Datapoints", [])
            if not points:
                return None
            return sum(p["Average"] for p in points) / len(points)
        except Exception:
            return None

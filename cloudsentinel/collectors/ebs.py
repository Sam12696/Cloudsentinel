from __future__ import annotations

import logging
from datetime import timedelta

from .base import BaseCollector

logger = logging.getLogger(__name__)


class EBSCollector(BaseCollector):
    name = "ebs"

    def collect(self, region: str) -> list[dict]:
        ec2 = self.client("ec2", region)
        cw = self.client("cloudwatch", region)
        volumes = []

        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate():
            for vol in page["Volumes"]:
                vid = vol["VolumeId"]
                state = vol["State"]
                size_gb = vol["Size"]
                vol_type = vol.get("VolumeType", "gp2")
                create_time = vol.get("CreateTime")
                attachments = vol.get("Attachments", [])
                is_attached = len(attachments) > 0
                instance_id = attachments[0].get("InstanceId") if is_attached else None
                iops = vol.get("Iops")
                throughput = vol.get("Throughput")
                tags = {t["Key"]: t["Value"] for t in vol.get("Tags", [])}
                name = tags.get("Name", vid)

                avg_read_ops = self._get_avg_metric(cw, vid, "VolumeReadOps", 14) if is_attached else None
                avg_write_ops = self._get_avg_metric(cw, vid, "VolumeWriteOps", 14) if is_attached else None

                monthly_cost = self._estimate_monthly_cost(vol_type, size_gb, iops)

                volumes.append({
                    "volume_id": vid,
                    "volume_name": name,
                    "volume_type": vol_type,
                    "state": state,
                    "region": region,
                    "size_gb": size_gb,
                    "is_attached": is_attached,
                    "attached_instance": instance_id,
                    "create_time": create_time,
                    "iops": iops,
                    "throughput": throughput,
                    "avg_read_ops_14d": avg_read_ops,
                    "avg_write_ops_14d": avg_write_ops,
                    "monthly_cost_usd": monthly_cost,
                    "tags": tags,
                })

        snapshots = self._collect_snapshots(ec2)
        return volumes + snapshots

    def _collect_snapshots(self, ec2) -> list[dict]:
        snaps = []
        try:
            owner_id = ec2.describe_account_attributes(
                AttributeNames=["default-vpc"]
            )
            paginator = ec2.get_paginator("describe_snapshots")
            for page in paginator.paginate(OwnerIds=["self"]):
                for snap in page["Snapshots"]:
                    sid = snap["SnapshotId"]
                    size_gb = snap.get("VolumeSize", 0)
                    start_time = snap.get("StartTime")
                    state = snap.get("State", "unknown")
                    tags = {t["Key"]: t["Value"] for t in snap.get("Tags", [])}
                    days_old = self.days_since(start_time) if start_time else 0

                    snaps.append({
                        "volume_id": f"snap:{sid}",
                        "volume_name": tags.get("Name", sid),
                        "volume_type": "snapshot",
                        "state": state,
                        "region": "",
                        "size_gb": size_gb,
                        "is_attached": False,
                        "attached_instance": None,
                        "create_time": start_time,
                        "iops": None,
                        "throughput": None,
                        "avg_read_ops_14d": None,
                        "avg_write_ops_14d": None,
                        "monthly_cost_usd": size_gb * 0.05,
                        "tags": tags,
                        "snapshot_days_old": days_old,
                    })
        except Exception:
            pass
        return snaps

    def _get_avg_metric(self, cw, volume_id: str, metric: str, days: int) -> float | None:
        try:
            end = self.utcnow()
            start = end - timedelta(days=days)
            resp = cw.get_metric_statistics(
                Namespace="AWS/EBS",
                MetricName=metric,
                Dimensions=[{"Name": "VolumeId", "Value": volume_id}],
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

    def _estimate_monthly_cost(self, vol_type: str, size_gb: int, iops: int | None) -> float:
        pricing = {"gp2": 0.10, "gp3": 0.08, "io1": 0.125, "io2": 0.125, "st1": 0.045, "sc1": 0.025}
        base = pricing.get(vol_type, 0.10) * size_gb
        if vol_type in ("io1", "io2") and iops:
            base += iops * 0.065
        return base

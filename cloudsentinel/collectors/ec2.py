from __future__ import annotations

import logging
from datetime import timedelta

from .base import BaseCollector

logger = logging.getLogger(__name__)

# On-demand pricing approximation ($/hr) for common instance types
INSTANCE_PRICING: dict[str, float] = {
    "t2.micro": 0.0116, "t2.small": 0.023, "t2.medium": 0.0464,
    "t2.large": 0.0928, "t2.xlarge": 0.1856, "t2.2xlarge": 0.3712,
    "t3.micro": 0.0104, "t3.small": 0.0208, "t3.medium": 0.0416,
    "t3.large": 0.0832, "t3.xlarge": 0.1664, "t3.2xlarge": 0.3328,
    "m5.large": 0.096, "m5.xlarge": 0.192, "m5.2xlarge": 0.384,
    "m5.4xlarge": 0.768, "m5.8xlarge": 1.536, "m5.16xlarge": 3.072,
    "c5.large": 0.085, "c5.xlarge": 0.17, "c5.2xlarge": 0.34,
    "c5.4xlarge": 0.68, "c5.9xlarge": 1.53, "c5.18xlarge": 3.06,
    "r5.large": 0.126, "r5.xlarge": 0.252, "r5.2xlarge": 0.504,
    "m6i.large": 0.096, "m6i.xlarge": 0.192, "m6i.2xlarge": 0.384,
    "c6i.large": 0.085, "c6i.xlarge": 0.17,
}


class EC2Collector(BaseCollector):
    name = "ec2"

    def collect(self, region: str) -> list[dict]:
        ec2 = self.client("ec2", region)
        cw = self.client("cloudwatch", region)
        instances = []

        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page["Reservations"]:
                for inst in reservation["Instances"]:
                    iid = inst["InstanceId"]
                    state = inst["State"]["Name"]
                    itype = inst.get("InstanceType", "unknown")
                    launch_time = inst.get("LaunchTime")
                    tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                    name = tags.get("Name", iid)

                    avg_cpu = self._get_avg_metric(cw, iid, "CPUUtilization", 14) if state == "running" else None
                    avg_net_in = self._get_avg_metric(cw, iid, "NetworkIn", 14) if state == "running" else None
                    avg_net_out = self._get_avg_metric(cw, iid, "NetworkOut", 14) if state == "running" else None

                    stopped_since = None
                    if state == "stopped" and launch_time:
                        stopped_since = self._get_stopped_since(ec2, iid)

                    hourly_cost = INSTANCE_PRICING.get(itype, 0.1)

                    instances.append({
                        "instance_id": iid,
                        "instance_name": name,
                        "instance_type": itype,
                        "state": state,
                        "region": region,
                        "launch_time": launch_time,
                        "avg_cpu_14d": avg_cpu,
                        "avg_network_in_14d": avg_net_in,
                        "avg_network_out_14d": avg_net_out,
                        "stopped_since": stopped_since,
                        "hourly_cost_usd": hourly_cost,
                        "monthly_cost_usd": hourly_cost * 730,
                        "tags": tags,
                        "platform": inst.get("Platform", "linux"),
                        "az": inst.get("Placement", {}).get("AvailabilityZone", ""),
                    })

        return instances

    def _get_avg_metric(self, cw, instance_id: str, metric: str, days: int) -> float | None:
        try:
            end = self.utcnow()
            start = end - timedelta(days=days)
            resp = cw.get_metric_statistics(
                Namespace="AWS/EC2",
                MetricName=metric,
                Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
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

    def _get_stopped_since(self, ec2, instance_id: str):
        try:
            resp = ec2.describe_instance_status(
                InstanceIds=[instance_id],
                IncludeAllInstances=True,
            )
            # fallback: use CloudTrail would be ideal; here we estimate
            return None
        except Exception:
            return None

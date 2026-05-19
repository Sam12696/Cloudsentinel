from __future__ import annotations

import logging
from datetime import timedelta

from .base import BaseCollector

logger = logging.getLogger(__name__)


class ELBCollector(BaseCollector):
    name = "elb"

    def collect(self, region: str) -> list[dict]:
        elb = self.client("elbv2", region)
        cw = self.client("cloudwatch", region)
        results = []

        paginator = elb.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            for lb in page["LoadBalancers"]:
                arn = lb["LoadBalancerArn"]
                name = lb["LoadBalancerName"]
                lb_type = lb.get("Type", "application")
                state = lb.get("State", {}).get("Code", "unknown")
                dns = lb.get("DNSName", "")
                tags = self._get_tags(elb, arn)

                target_groups = self._get_target_groups(elb, arn)
                healthy_targets = sum(tg["healthy"] for tg in target_groups)
                total_targets = sum(tg["total"] for tg in target_groups)

                dim_name = "ApplicationELB" if lb_type == "application" else "NetworkELB"
                lb_dim = arn.split(":")[-1].replace("loadbalancer/", "")
                avg_requests = self._get_avg_metric(cw, dim_name, lb_dim, "RequestCount", 14)

                monthly_cost = 16.43 if lb_type == "application" else 16.43

                results.append({
                    "lb_arn": arn,
                    "lb_name": name,
                    "lb_type": lb_type,
                    "state": state,
                    "region": region,
                    "dns_name": dns,
                    "target_groups": target_groups,
                    "healthy_targets": healthy_targets,
                    "total_targets": total_targets,
                    "avg_requests_14d": avg_requests,
                    "monthly_cost_usd": monthly_cost,
                    "tags": tags,
                })

        return results

    def _get_target_groups(self, elb, lb_arn: str) -> list[dict]:
        tgs = []
        try:
            paginator = elb.get_paginator("describe_target_groups")
            for page in paginator.paginate(LoadBalancerArn=lb_arn):
                for tg in page["TargetGroups"]:
                    tg_arn = tg["TargetGroupArn"]
                    try:
                        health = elb.describe_target_health(TargetGroupArn=tg_arn)
                        targets = health.get("TargetHealthDescriptions", [])
                        healthy = sum(1 for t in targets if t["TargetHealth"]["State"] == "healthy")
                        tgs.append({
                            "arn": tg_arn,
                            "name": tg.get("TargetGroupName", ""),
                            "total": len(targets),
                            "healthy": healthy,
                        })
                    except Exception:
                        tgs.append({"arn": tg_arn, "name": tg.get("TargetGroupName", ""), "total": 0, "healthy": 0})
        except Exception:
            pass
        return tgs

    def _get_avg_metric(self, cw, namespace_suffix: str, lb_dim: str, metric: str, days: int) -> float | None:
        try:
            end = self.utcnow()
            start = end - timedelta(days=days)
            resp = cw.get_metric_statistics(
                Namespace=f"AWS/{namespace_suffix}",
                MetricName=metric,
                Dimensions=[{"Name": "LoadBalancer", "Value": lb_dim}],
                StartTime=start,
                EndTime=end,
                Period=86400,
                Statistics=["Sum"],
            )
            points = resp.get("Datapoints", [])
            if not points:
                return 0.0
            return sum(p["Sum"] for p in points) / len(points)
        except Exception:
            return None

    def _get_tags(self, elb, arn: str) -> dict:
        try:
            resp = elb.describe_tags(ResourceArns=[arn])
            for desc in resp.get("TagDescriptions", []):
                return {t["Key"]: t["Value"] for t in desc.get("Tags", [])}
        except Exception:
            pass
        return {}

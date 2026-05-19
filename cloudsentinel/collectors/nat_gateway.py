from __future__ import annotations

import logging
from datetime import timedelta

from .base import BaseCollector

logger = logging.getLogger(__name__)


class NATGatewayCollector(BaseCollector):
    name = "nat_gateway"

    def collect(self, region: str) -> list[dict]:
        ec2 = self.client("ec2", region)
        cw = self.client("cloudwatch", region)
        gateways = []

        try:
            paginator = ec2.get_paginator("describe_nat_gateways")
            for page in paginator.paginate(Filter=[{"Name": "state", "Values": ["available"]}]):
                for gw in page["NatGateways"]:
                    gw_id = gw["NatGatewayId"]
                    vpc_id = gw.get("VpcId", "")
                    subnet_id = gw.get("SubnetId", "")
                    state = gw.get("State", "unknown")
                    create_time = gw.get("CreateTime")
                    tags = {t["Key"]: t["Value"] for t in gw.get("Tags", [])}

                    bytes_out = self._get_sum_metric(cw, gw_id, "BytesOutToDestination", 30)
                    bytes_in = self._get_sum_metric(cw, gw_id, "BytesInFromDestination", 30)
                    active_connections = self._get_avg_metric(cw, gw_id, "ActiveConnectionCount", 30)
                    packet_drops = self._get_sum_metric(cw, gw_id, "PacketsDropCount", 30)

                    total_gb = ((bytes_out or 0) + (bytes_in or 0)) / (1024 ** 3)
                    data_processing_cost = total_gb * 0.045
                    hourly_cost = 0.045
                    monthly_cost = hourly_cost * 730 + data_processing_cost

                    gateways.append({
                        "gateway_id": gw_id,
                        "vpc_id": vpc_id,
                        "subnet_id": subnet_id,
                        "state": state,
                        "region": region,
                        "create_time": create_time,
                        "bytes_out_30d": bytes_out,
                        "bytes_in_30d": bytes_in,
                        "total_data_gb_30d": total_gb,
                        "active_connections_avg": active_connections,
                        "packet_drops_30d": packet_drops,
                        "data_processing_cost_30d_usd": data_processing_cost,
                        "monthly_cost_usd": monthly_cost,
                        "tags": tags,
                    })
        except Exception as exc:
            logger.warning("NAT Gateway collection failed in %s: %s", region, exc)

        return gateways

    def _get_sum_metric(self, cw, gw_id: str, metric: str, days: int) -> float | None:
        try:
            end = self.utcnow()
            start = end - timedelta(days=days)
            resp = cw.get_metric_statistics(
                Namespace="AWS/NATGateway",
                MetricName=metric,
                Dimensions=[{"Name": "NatGatewayId", "Value": gw_id}],
                StartTime=start,
                EndTime=end,
                Period=days * 86400,
                Statistics=["Sum"],
            )
            points = resp.get("Datapoints", [])
            return sum(p["Sum"] for p in points) if points else 0.0
        except Exception:
            return None

    def _get_avg_metric(self, cw, gw_id: str, metric: str, days: int) -> float | None:
        try:
            end = self.utcnow()
            start = end - timedelta(days=days)
            resp = cw.get_metric_statistics(
                Namespace="AWS/NATGateway",
                MetricName=metric,
                Dimensions=[{"Name": "NatGatewayId", "Value": gw_id}],
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

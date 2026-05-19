from __future__ import annotations

import logging
from datetime import timedelta

from .base import BaseCollector

logger = logging.getLogger(__name__)


class DynamoDBCollector(BaseCollector):
    name = "dynamodb"

    def collect(self, region: str) -> list[dict]:
        ddb = self.client("dynamodb", region)
        cw = self.client("cloudwatch", region)
        tables = []

        paginator = ddb.get_paginator("list_tables")
        for page in paginator.paginate():
            for table_name in page.get("TableNames", []):
                try:
                    desc = ddb.describe_table(TableName=table_name)["Table"]
                    status = desc.get("TableStatus", "unknown")
                    item_count = desc.get("ItemCount", 0)
                    size_bytes = desc.get("TableSizeBytes", 0)
                    billing_mode = desc.get("BillingModeSummary", {}).get("BillingMode", "PROVISIONED")
                    provisioned = desc.get("ProvisionedThroughput", {})
                    read_capacity = provisioned.get("ReadCapacityUnits", 0)
                    write_capacity = provisioned.get("WriteCapacityUnits", 0)
                    tags = self._get_tags(ddb, desc.get("TableArn", ""))

                    consumed_read = self._get_avg_metric(cw, table_name, "ConsumedReadCapacityUnits", 14)
                    consumed_write = self._get_avg_metric(cw, table_name, "ConsumedWriteCapacityUnits", 14)
                    throttled_reads = self._get_sum_metric(cw, table_name, "ReadThrottleEvents", 14)
                    throttled_writes = self._get_sum_metric(cw, table_name, "WriteThrottleEvents", 14)

                    read_util = (consumed_read / read_capacity * 100) if read_capacity and consumed_read else None
                    write_util = (consumed_write / write_capacity * 100) if write_capacity and consumed_write else None

                    monthly_cost = self._estimate_cost(
                        billing_mode, read_capacity, write_capacity, size_bytes
                    )

                    tables.append({
                        "table_name": table_name,
                        "table_arn": desc.get("TableArn", ""),
                        "status": status,
                        "region": region,
                        "item_count": item_count,
                        "size_bytes": size_bytes,
                        "billing_mode": billing_mode,
                        "read_capacity_units": read_capacity,
                        "write_capacity_units": write_capacity,
                        "consumed_read_14d": consumed_read,
                        "consumed_write_14d": consumed_write,
                        "throttled_reads_14d": throttled_reads,
                        "throttled_writes_14d": throttled_writes,
                        "read_utilization_pct": read_util,
                        "write_utilization_pct": write_util,
                        "monthly_cost_usd": monthly_cost,
                        "tags": tags,
                    })
                except Exception as exc:
                    logger.warning("DynamoDB table %s failed: %s", table_name, exc)

        return tables

    def _get_avg_metric(self, cw, table_name: str, metric: str, days: int) -> float | None:
        try:
            end = self.utcnow()
            start = end - timedelta(days=days)
            resp = cw.get_metric_statistics(
                Namespace="AWS/DynamoDB",
                MetricName=metric,
                Dimensions=[{"Name": "TableName", "Value": table_name}],
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

    def _get_sum_metric(self, cw, table_name: str, metric: str, days: int) -> float | None:
        try:
            end = self.utcnow()
            start = end - timedelta(days=days)
            resp = cw.get_metric_statistics(
                Namespace="AWS/DynamoDB",
                MetricName=metric,
                Dimensions=[{"Name": "TableName", "Value": table_name}],
                StartTime=start,
                EndTime=end,
                Period=days * 86400,
                Statistics=["Sum"],
            )
            points = resp.get("Datapoints", [])
            return sum(p["Sum"] for p in points) if points else 0.0
        except Exception:
            return None

    def _estimate_cost(self, billing_mode: str, rcu: int, wcu: int, size_bytes: int) -> float:
        storage_cost = (size_bytes / (1024 ** 3)) * 0.25
        if billing_mode == "PAY_PER_REQUEST":
            return storage_cost
        return (rcu * 0.00013 + wcu * 0.00065) * 730 + storage_cost

    def _get_tags(self, ddb, arn: str) -> dict:
        try:
            resp = ddb.list_tags_of_resource(ResourceArn=arn)
            return {t["Key"]: t["Value"] for t in resp.get("Tags", [])}
        except Exception:
            return {}

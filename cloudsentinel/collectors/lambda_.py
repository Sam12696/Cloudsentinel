from __future__ import annotations

import logging
from datetime import timedelta

from .base import BaseCollector

logger = logging.getLogger(__name__)


class LambdaCollector(BaseCollector):
    name = "lambda"

    def collect(self, region: str) -> list[dict]:
        lam = self.client("lambda", region)
        cw = self.client("cloudwatch", region)
        functions = []

        paginator = lam.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page["Functions"]:
                fname = fn["FunctionName"]
                memory_mb = fn.get("MemorySize", 128)
                timeout_sec = fn.get("Timeout", 3)
                runtime = fn.get("Runtime", "unknown")
                last_modified = fn.get("LastModified")
                code_size = fn.get("CodeSize", 0)
                tags = self._get_tags(lam, fn["FunctionArn"])

                invocations = self._get_sum_metric(cw, fname, "Invocations", 30)
                errors = self._get_sum_metric(cw, fname, "Errors", 30)
                avg_duration = self._get_avg_metric(cw, fname, "Duration", 30)
                throttles = self._get_sum_metric(cw, fname, "Throttles", 30)
                concurrent = self._get_avg_metric(cw, fname, "ConcurrentExecutions", 30)

                estimated_monthly_cost = self._estimate_cost(
                    invocations or 0, avg_duration or 0, memory_mb
                )

                functions.append({
                    "function_name": fname,
                    "function_arn": fn["FunctionArn"],
                    "runtime": runtime,
                    "memory_mb": memory_mb,
                    "timeout_sec": timeout_sec,
                    "region": region,
                    "last_modified": last_modified,
                    "code_size_bytes": code_size,
                    "invocations_30d": invocations,
                    "errors_30d": errors,
                    "avg_duration_ms_30d": avg_duration,
                    "throttles_30d": throttles,
                    "avg_concurrent_executions": concurrent,
                    "estimated_monthly_cost_usd": estimated_monthly_cost,
                    "tags": tags,
                    "has_dlq": "DeadLetterConfig" in fn and bool(fn["DeadLetterConfig"]),
                })

        return functions

    def _get_sum_metric(self, cw, function_name: str, metric: str, days: int) -> float | None:
        try:
            end = self.utcnow()
            start = end - timedelta(days=days)
            resp = cw.get_metric_statistics(
                Namespace="AWS/Lambda",
                MetricName=metric,
                Dimensions=[{"Name": "FunctionName", "Value": function_name}],
                StartTime=start,
                EndTime=end,
                Period=days * 86400,
                Statistics=["Sum"],
            )
            points = resp.get("Datapoints", [])
            return sum(p["Sum"] for p in points) if points else 0.0
        except Exception:
            return None

    def _get_avg_metric(self, cw, function_name: str, metric: str, days: int) -> float | None:
        try:
            end = self.utcnow()
            start = end - timedelta(days=days)
            resp = cw.get_metric_statistics(
                Namespace="AWS/Lambda",
                MetricName=metric,
                Dimensions=[{"Name": "FunctionName", "Value": function_name}],
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

    def _estimate_cost(self, invocations: float, avg_duration_ms: float, memory_mb: int) -> float:
        gb_seconds = (memory_mb / 1024) * (avg_duration_ms / 1000) * invocations
        # $0.0000166667 per GB-second, $0.20 per million requests
        compute_cost = gb_seconds * 0.0000166667
        request_cost = (invocations / 1_000_000) * 0.20
        return compute_cost + request_cost

    def _get_tags(self, lam, function_arn: str) -> dict:
        try:
            return lam.list_tags(Resource=function_arn).get("Tags", {})
        except Exception:
            return {}

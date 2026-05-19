from __future__ import annotations

import logging
from datetime import timedelta

from .base import BaseCollector

logger = logging.getLogger(__name__)


class CloudFrontCollector(BaseCollector):
    name = "cloudfront"

    def collect(self, region: str) -> list[dict]:
        if region != "us-east-1":
            return []

        cf = self.client("cloudfront", "us-east-1")
        cw = self.client("cloudwatch", "us-east-1")
        distributions = []

        try:
            paginator = cf.get_paginator("list_distributions")
            for page in paginator.paginate():
                dist_list = page.get("DistributionList", {})
                for dist in dist_list.get("Items", []):
                    dist_id = dist["Id"]
                    domain = dist.get("DomainName", "")
                    enabled = dist.get("Enabled", False)
                    status = dist.get("Status", "unknown")
                    origins = [o["DomainName"] for o in dist.get("Origins", {}).get("Items", [])]
                    price_class = dist.get("PriceClass", "PriceClass_All")
                    tags = self._get_tags(cf, dist.get("ARN", ""))

                    requests = self._get_sum_metric(cw, dist_id, "Requests", 30)
                    bytes_downloaded = self._get_sum_metric(cw, dist_id, "BytesDownloaded", 30)
                    cache_hits = self._get_sum_metric(cw, dist_id, "CacheHitRate", 30)
                    error_rate = self._get_avg_metric(cw, dist_id, "5xxErrorRate", 30)

                    distributions.append({
                        "distribution_id": dist_id,
                        "domain_name": domain,
                        "enabled": enabled,
                        "status": status,
                        "origins": origins,
                        "price_class": price_class,
                        "region": "global",
                        "requests_30d": requests,
                        "bytes_downloaded_30d": bytes_downloaded,
                        "cache_hit_rate_30d": cache_hits,
                        "error_rate_5xx_30d": error_rate,
                        "tags": tags,
                    })
        except Exception as exc:
            logger.warning("CloudFront collection failed: %s", exc)

        return distributions

    def _get_sum_metric(self, cw, dist_id: str, metric: str, days: int) -> float | None:
        try:
            end = self.utcnow()
            start = end - timedelta(days=days)
            resp = cw.get_metric_statistics(
                Namespace="AWS/CloudFront",
                MetricName=metric,
                Dimensions=[{"Name": "DistributionId", "Value": dist_id}],
                StartTime=start,
                EndTime=end,
                Period=days * 86400,
                Statistics=["Sum"],
            )
            points = resp.get("Datapoints", [])
            return sum(p["Sum"] for p in points) if points else 0.0
        except Exception:
            return None

    def _get_avg_metric(self, cw, dist_id: str, metric: str, days: int) -> float | None:
        try:
            end = self.utcnow()
            start = end - timedelta(days=days)
            resp = cw.get_metric_statistics(
                Namespace="AWS/CloudFront",
                MetricName=metric,
                Dimensions=[{"Name": "DistributionId", "Value": dist_id}],
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

    def _get_tags(self, cf, arn: str) -> dict:
        try:
            resp = cf.list_tags_for_resource(Resource=arn)
            return {t["Key"]: t["Value"] for t in resp.get("Tags", {}).get("Items", [])}
        except Exception:
            return {}

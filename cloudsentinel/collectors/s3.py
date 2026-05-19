from __future__ import annotations

import logging
from datetime import datetime, timezone

from .base import BaseCollector

logger = logging.getLogger(__name__)


class S3Collector(BaseCollector):
    name = "s3"

    def collect(self, region: str) -> list[dict]:
        s3 = self.client("s3", region)
        cw = self.client("cloudwatch", region)
        buckets_data: list[dict] = []

        try:
            response = s3.list_buckets()
        except Exception as exc:
            logger.warning("Cannot list S3 buckets: %s", exc)
            return []

        for bucket in response.get("Buckets", []):
            name = bucket["Name"]
            creation_date = bucket.get("CreationDate", datetime.now(timezone.utc))

            try:
                loc = s3.get_bucket_location(Bucket=name)
                bucket_region = loc.get("LocationConstraint") or "us-east-1"
            except Exception:
                bucket_region = "us-east-1"

            size_bytes = self._get_bucket_size(cw, name, bucket_region)
            object_count = self._get_object_count(cw, name, bucket_region)
            last_modified = self._get_last_modified(s3, name)
            storage_classes = self._get_storage_class_distribution(s3, name)
            has_lifecycle = self._has_lifecycle_policy(s3, name)
            is_public = self._is_public(s3, name)
            has_versioning = self._has_versioning(s3, name)
            incomplete_mpu_size = self._get_incomplete_multipart_size(s3, name)
            tags = self._get_tags(s3, name)

            buckets_data.append({
                "bucket_name": name,
                "region": bucket_region,
                "creation_date": creation_date,
                "size_bytes": size_bytes,
                "object_count": object_count,
                "last_modified": last_modified,
                "storage_classes": storage_classes,
                "has_lifecycle_policy": has_lifecycle,
                "is_public": is_public,
                "has_versioning": has_versioning,
                "incomplete_mpu_bytes": incomplete_mpu_size,
                "tags": tags,
            })

        return buckets_data

    def _get_bucket_size(self, cw, bucket_name: str, region: str) -> float:
        try:
            resp = cw.get_metric_statistics(
                Namespace="AWS/S3",
                MetricName="BucketSizeBytes",
                Dimensions=[
                    {"Name": "BucketName", "Value": bucket_name},
                    {"Name": "StorageType", "Value": "StandardStorage"},
                ],
                StartTime=self.utcnow().replace(hour=0, minute=0, second=0) - __import__("datetime").timedelta(days=2),
                EndTime=self.utcnow(),
                Period=86400,
                Statistics=["Average"],
            )
            points = resp.get("Datapoints", [])
            return max((p["Average"] for p in points), default=0.0)
        except Exception:
            return 0.0

    def _get_object_count(self, cw, bucket_name: str, region: str) -> int:
        try:
            resp = cw.get_metric_statistics(
                Namespace="AWS/S3",
                MetricName="NumberOfObjects",
                Dimensions=[
                    {"Name": "BucketName", "Value": bucket_name},
                    {"Name": "StorageType", "Value": "AllStorageTypes"},
                ],
                StartTime=self.utcnow().replace(hour=0, minute=0, second=0) - __import__("datetime").timedelta(days=2),
                EndTime=self.utcnow(),
                Period=86400,
                Statistics=["Average"],
            )
            points = resp.get("Datapoints", [])
            return int(max((p["Average"] for p in points), default=0))
        except Exception:
            return 0

    def _get_last_modified(self, s3, bucket_name: str):
        try:
            resp = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=1000)
            objects = resp.get("Contents", [])
            if not objects:
                return None
            return max(o["LastModified"] for o in objects)
        except Exception:
            return None

    def _get_storage_class_distribution(self, s3, bucket_name: str) -> dict:
        classes: dict[str, int] = {}
        try:
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket_name, PaginationConfig={"MaxItems": 5000}):
                for obj in page.get("Contents", []):
                    sc = obj.get("StorageClass", "STANDARD")
                    classes[sc] = classes.get(sc, 0) + 1
        except Exception:
            pass
        return classes

    def _has_lifecycle_policy(self, s3, bucket_name: str) -> bool:
        try:
            s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            return True
        except Exception:
            return False

    def _is_public(self, s3, bucket_name: str) -> bool:
        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if grantee.get("URI", "").endswith("AllUsers"):
                    return True
        except Exception:
            pass
        return False

    def _has_versioning(self, s3, bucket_name: str) -> bool:
        try:
            resp = s3.get_bucket_versioning(Bucket=bucket_name)
            return resp.get("Status") == "Enabled"
        except Exception:
            return False

    def _get_incomplete_multipart_size(self, s3, bucket_name: str) -> float:
        total = 0.0
        try:
            paginator = s3.get_paginator("list_multipart_uploads")
            for page in paginator.paginate(Bucket=bucket_name):
                for upload in page.get("Uploads", []):
                    parts_resp = s3.list_parts(
                        Bucket=bucket_name,
                        Key=upload["Key"],
                        UploadId=upload["UploadId"],
                    )
                    for part in parts_resp.get("Parts", []):
                        total += part.get("Size", 0)
        except Exception:
            pass
        return total

    def _get_tags(self, s3, bucket_name: str) -> dict:
        try:
            resp = s3.get_bucket_tagging(Bucket=bucket_name)
            return {t["Key"]: t["Value"] for t in resp.get("TagSet", [])}
        except Exception:
            return {}

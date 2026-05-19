from __future__ import annotations

import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)


class ElasticIPCollector(BaseCollector):
    name = "elastic_ip"

    def collect(self, region: str) -> list[dict]:
        ec2 = self.client("ec2", region)
        eips = []

        try:
            resp = ec2.describe_addresses()
            for addr in resp.get("Addresses", []):
                allocation_id = addr.get("AllocationId", addr.get("PublicIp", ""))
                public_ip = addr.get("PublicIp", "")
                private_ip = addr.get("PrivateIpAddress")
                instance_id = addr.get("InstanceId")
                association_id = addr.get("AssociationId")
                is_attached = association_id is not None or instance_id is not None
                network_interface = addr.get("NetworkInterfaceId")
                tags = {t["Key"]: t["Value"] for t in addr.get("Tags", [])}
                name = tags.get("Name", public_ip)

                # Unattached EIP costs $3.65/month
                monthly_cost = 0.0 if is_attached else 3.65

                eips.append({
                    "allocation_id": allocation_id,
                    "eip_name": name,
                    "public_ip": public_ip,
                    "private_ip": private_ip,
                    "instance_id": instance_id,
                    "association_id": association_id,
                    "network_interface": network_interface,
                    "is_attached": is_attached,
                    "region": region,
                    "monthly_cost_usd": monthly_cost,
                    "tags": tags,
                })
        except Exception as exc:
            logger.warning("Elastic IP collection failed in %s: %s", region, exc)

        return eips

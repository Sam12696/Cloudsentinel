from __future__ import annotations

import logging
from datetime import datetime, timezone

from .base import BaseCollector

logger = logging.getLogger(__name__)


class IAMCollector(BaseCollector):
    name = "iam"

    def collect(self, region: str) -> list[dict]:
        if region != "us-east-1":
            return []

        iam = self.client("iam", "us-east-1")
        findings = []

        findings.extend(self._collect_users(iam))
        findings.extend(self._collect_roles(iam))
        return findings

    def _collect_users(self, iam) -> list[dict]:
        users = []
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                uname = user["UserName"]
                create_date = user.get("CreateDate")
                password_last_used = user.get("PasswordLastUsed")

                if password_last_used:
                    days_since_login = self.days_since(password_last_used)
                elif create_date:
                    days_since_login = self.days_since(create_date)
                else:
                    days_since_login = 9999

                access_keys = self._get_access_key_info(iam, uname)
                mfa_enabled = self._has_mfa(iam, uname)
                attached_policies = self._get_attached_policies(iam, uname)
                tags = {t["Key"]: t["Value"] for t in user.get("Tags", [])}

                users.append({
                    "resource_type": "iam_user",
                    "user_name": uname,
                    "user_arn": user["Arn"],
                    "region": "global",
                    "create_date": create_date,
                    "password_last_used": password_last_used,
                    "days_since_login": days_since_login,
                    "access_keys": access_keys,
                    "mfa_enabled": mfa_enabled,
                    "attached_policies": attached_policies,
                    "monthly_cost_usd": 0.0,
                    "tags": tags,
                })

        return users

    def _collect_roles(self, iam) -> list[dict]:
        roles = []
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                rname = role["RoleName"]
                create_date = role.get("CreateDate")
                last_used = role.get("RoleLastUsed", {})
                last_used_date = last_used.get("LastUsedDate")
                days_since_used = self.days_since(last_used_date) if last_used_date else 9999

                tags = {t["Key"]: t["Value"] for t in role.get("Tags", [])}

                roles.append({
                    "resource_type": "iam_role",
                    "user_name": rname,
                    "user_arn": role["Arn"],
                    "region": "global",
                    "create_date": create_date,
                    "password_last_used": last_used_date,
                    "days_since_login": days_since_used,
                    "access_keys": [],
                    "mfa_enabled": None,
                    "attached_policies": [],
                    "monthly_cost_usd": 0.0,
                    "tags": tags,
                })

        return roles

    def _get_access_key_info(self, iam, username: str) -> list[dict]:
        keys = []
        try:
            resp = iam.list_access_keys(UserName=username)
            for key in resp.get("AccessKeyMetadata", []):
                kid = key["AccessKeyId"]
                status = key["Status"]
                create_date = key.get("CreateDate")
                days_old = self.days_since(create_date) if create_date else 0
                try:
                    last_used_resp = iam.get_access_key_last_used(AccessKeyId=kid)
                    last_used = last_used_resp.get("AccessKeyLastUsed", {}).get("LastUsedDate")
                    days_since_used = self.days_since(last_used) if last_used else days_old
                except Exception:
                    last_used = None
                    days_since_used = days_old

                keys.append({
                    "key_id": kid,
                    "status": status,
                    "days_old": days_old,
                    "days_since_used": days_since_used,
                    "last_used": last_used,
                })
        except Exception:
            pass
        return keys

    def _has_mfa(self, iam, username: str) -> bool:
        try:
            resp = iam.list_mfa_devices(UserName=username)
            return len(resp.get("MFADevices", [])) > 0
        except Exception:
            return False

    def _get_attached_policies(self, iam, username: str) -> list[str]:
        try:
            resp = iam.list_attached_user_policies(UserName=username)
            return [p["PolicyName"] for p in resp.get("AttachedPolicies", [])]
        except Exception:
            return []

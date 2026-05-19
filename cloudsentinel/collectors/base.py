from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import boto3

if TYPE_CHECKING:
    from cloudsentinel.config import Config

logger = logging.getLogger(__name__)


class BaseCollector(ABC):
    name: str = "base"

    def __init__(self, config: "Config") -> None:
        self.config = config

    def session(self, region: str) -> boto3.Session:
        return self.config.get_session(region=region)

    def client(self, service: str, region: str):
        return self.session(region).client(service, region_name=region)

    def resource(self, service: str, region: str):
        return self.session(region).resource(service, region_name=region)

    def utcnow(self) -> datetime:
        return datetime.now(timezone.utc)

    def days_since(self, dt: datetime) -> float:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (self.utcnow() - dt).total_seconds() / 86400

    @abstractmethod
    def collect(self, region: str) -> list[dict]:
        """Collect raw resource data for the given region."""

    def safe_collect(self, region: str) -> list[dict]:
        try:
            return self.collect(region)
        except Exception as exc:
            logger.warning("Collector %s failed in %s: %s", self.name, region, exc)
            return []

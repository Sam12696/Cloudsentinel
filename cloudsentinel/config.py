from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

import boto3


@dataclass
class Config:
    profile: Optional[str] = None
    region: Optional[str] = None
    regions: list[str] = field(default_factory=list)
    bedrock_model_id: str = "anthropic.claude-3-haiku-20240307-v1:0"
    bedrock_region: str = "us-east-1"
    days_threshold: int = 90
    cpu_threshold: float = 5.0
    network_threshold: float = 5.0
    enable_ai: bool = True
    output_json: Optional[str] = None
    output_html: Optional[str] = None
    services: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.region:
            self.region = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        if not self.bedrock_region:
            self.bedrock_region = os.environ.get("BEDROCK_REGION", "us-east-1")
        if not self.bedrock_model_id:
            self.bedrock_model_id = os.environ.get(
                "BEDROCK_MODEL_ID", "anthropic.claude-3-haiku-20240307-v1:0"
            )

    def get_session(self, region: Optional[str] = None) -> boto3.Session:
        return boto3.Session(
            profile_name=self.profile,
            region_name=region or self.region,
        )

    def get_bedrock_client(self):
        session = self.get_session(region=self.bedrock_region)
        return session.client("bedrock-runtime", region_name=self.bedrock_region)

    @property
    def active_regions(self) -> list[str]:
        if self.regions:
            return self.regions
        return [self.region or "us-east-1"]


ALL_SERVICES = [
    "s3", "ec2", "rds", "lambda", "ebs",
    "elb", "cloudfront", "nat_gateway", "elastic_ip",
    "dynamodb", "iam",
]

"""密钥生成与查询的业务逻辑。"""

from __future__ import annotations

import base64
import os
import uuid
from datetime import datetime, timezone
from typing import Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .store import KeyStore

SUPPORTED_ALGORITHMS = ("AES256", "RSA2048")


class ValidationError(ValueError):
    """请求字段校验失败，message 指出具体字段。"""


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class KeyService:
    """密钥生成与读取，依赖 KeyStore 持久化。"""

    def __init__(self, store: KeyStore) -> None:
        self.store = store

    def generate(self, tenant_id: str, algorithm: str, label: str) -> dict:
        """生成密钥并持久化，返回公开视图（不含私钥材料）。"""
        tenant_id, algorithm, label = validate_generate_request(
            {"tenant_id": tenant_id, "algorithm": algorithm, "label": label}
        )
        if algorithm == "AES256":
            private_material = base64.b64encode(os.urandom(32)).decode("ascii")
            public_key = None
        else:  # RSA2048
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            private_material = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("ascii")
            public_key = key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("ascii")

        record = {
            "key_id": uuid.uuid4().hex,
            "tenant_id": tenant_id,
            "algorithm": algorithm,
            "label": label,
            "created_at": _utc_now_iso(),
            "public_key": public_key,
            "private_key": private_material,
        }
        self.store.save(tenant_id, record)
        return {
            "key_id": record["key_id"],
            "algorithm": record["algorithm"],
            "public_key": record["public_key"],
        }

    def get(self, tenant_id: str, key_id: str) -> Optional[dict]:
        """按租户读取密钥公开视图，不存在返回 None。"""
        record = self.store.load(tenant_id, key_id)
        if record is None:
            return None
        return {
            "key_id": record["key_id"],
            "algorithm": record["algorithm"],
            "label": record["label"],
            "created_at": record["created_at"],
            "public_key": record["public_key"],
        }


def validate_generate_request(payload: object) -> Tuple[str, str, str]:
    """校验 POST /v1/keys 请求体，返回 (tenant_id, algorithm, label)。"""
    if not isinstance(payload, dict):
        raise ValidationError("request body must be a JSON object")
    values = {}
    for field in ("tenant_id", "algorithm", "label"):
        value = payload.get(field)
        if value is None:
            raise ValidationError(f"missing required field: {field}")
        if not isinstance(value, str) or not value:
            raise ValidationError(f"field {field} must be a non-empty string")
        values[field] = value
    if values["algorithm"] not in SUPPORTED_ALGORITHMS:
        raise ValidationError(
            f"unsupported algorithm: {values['algorithm']!r} "
            f"(supported: {', '.join(SUPPORTED_ALGORITHMS)})"
        )
    return values["tenant_id"], values["algorithm"], values["label"]

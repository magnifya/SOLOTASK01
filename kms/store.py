"""密钥记录的磁盘持久化层。"""

from __future__ import annotations

import json
import os
import re
from typing import Optional

DEFAULT_DATA_DIR = os.path.join(os.getcwd(), "kms_data")

_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _check_name(kind: str, value: str) -> None:
    """拒绝空值与可能造成路径穿越的租户名 / 密钥 ID。"""
    if not isinstance(value, str) or not _SAFE_NAME.match(value) or ".." in value:
        raise ValueError(f"invalid {kind}: {value!r}")


class KeyStore:
    """按租户隔离的密钥记录存储。

    布局：{data_dir}/{tenant_id}/{key_id}.json
    """

    def __init__(self, data_dir: str = DEFAULT_DATA_DIR) -> None:
        self.data_dir = data_dir

    def _path(self, tenant_id: str, key_id: str) -> str:
        _check_name("tenant_id", tenant_id)
        _check_name("key_id", key_id)
        return os.path.join(self.data_dir, tenant_id, key_id + ".json")

    def save(self, tenant_id: str, record: dict) -> None:
        """将密钥记录原子写入磁盘。"""
        path = self._path(tenant_id, record["key_id"])
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(record, fh, ensure_ascii=False)
        os.replace(tmp, path)

    def load(self, tenant_id: str, key_id: str) -> Optional[dict]:
        """读取指定租户的密钥记录，不存在时返回 None。"""
        try:
            path = self._path(tenant_id, key_id)
        except ValueError:
            return None
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError):
            return None

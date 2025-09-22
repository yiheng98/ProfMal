from __future__ import annotations


class CPGNode:
    def __init__(self, node_id: int):
        self.node_id = node_id
        self.attr = {}

    def get_id(self) -> int:
        return self.node_id

    def get_attr(self) -> dict:
        return self.attr

    def get_value(self, key: str) -> str | None:
        if key in self.attr:
            return self.attr[key]
        else:
            return None

    def set_attr(self, key: str, value: str):
        self.attr[key] = value

class Edge:
    def __init__(self, edge_id: tuple[int, int]):
        self.edge_id: tuple[int, int] = edge_id  # (head, tail)
        self.attr: list[str] = []

    def get_id(self) -> tuple[int, int]:
        return self.edge_id

    def get_attr(self) -> list:
        return self.attr

    def add_attr(self, attr: str):
        self.attr.append(attr)

    def change_attr(self, attr: list):
        self.attr = attr

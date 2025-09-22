from __future__ import annotations
from npm_pipeline.classes.object import Object


class PDGNode:
    def __init__(self, node_id):
        self.node_id = node_id  # 节点ID
        self.source_pdg = None  # 属于哪个PDG图中的点
        self.node_type = None  # PDG点的类型 对应pdg中的NODE_TYPE
        self.line_number: int | None = None  # 行号开始位置
        self.line_number_end: int | None = None  # 行号结束位置
        self.column_number: int | None = None  # 列号开始位置
        self.column_number_end: int | None = None  # 列号结束位置
        self.name = None  # 对应PDG中的NAME
        self.filename = None  # 该点所在文件
        self.code = None  # 对应PDG中的CODE
        self.sensitive_node = False  # 是否是敏感节点
        self.is_entrance = False  # PDG图的起始点
        self.is_return = False  # PDG图的返回节点
        self.call_type = None  # 该PDG node在NODE_TYPE为call的类型下的call类型 CALL FUNCTION_CALL etc
        self.function_behavior = None  # 该PDG node的类型如果为函数调用，则记录该函数的行为图(pbg)
        self.node_full_name: tuple[Object, list[str]] | None = None  # 记录当前节点的full name
        self.return_value = None  # 如果是返回节点，则记录返回的内容
        self.branch = False
        self.sensitive_dict = None
        self.sensitive_degree = 0.5

    def __lt__(self, other):
        return self.line_number < other.line_number

    def set_source_pdg(self, pdg_id):
        self.source_pdg = pdg_id

    def get_source_pdg(self):
        return self.source_pdg

    def get_call_type(self):
        return self.call_type

    def set_call_type(self, call_type):
        self.call_type = call_type

    def get_behavior_of_call(self):
        return self.function_behavior

    def set_behavior_of_call(self, diagram):
        self.function_behavior = diagram

    def get_id(self):
        return self.node_id

    def get_node_type(self):
        return self.node_type

    def set_node_type(self, label):
        self.node_type = label

    def get_line_number(self) -> int:
        return self.line_number

    def set_line_number(self, line_number: int | None):
        self.line_number = line_number

    def get_line_number_end(self) -> int:
        return self.line_number_end

    def set_line_number_end(self, line_number_end: int | None):
        self.line_number_end = line_number_end

    def get_column_number(self) -> int:
        return self.column_number

    def set_column_number(self, column_number: int | None):
        self.column_number = column_number

    def get_column_number_end(self):
        return self.column_number_end

    def set_column_number_end(self, column_number_end: int | None):
        self.column_number_end = column_number_end

    def set_sensitive_node(self, bool_value):
        self.sensitive_node = bool_value

    def is_sensitive_node(self):
        return self.sensitive_node

    def set_entrance(self, bool_value):
        self.is_entrance = bool_value

    def is_entrance(self):
        return self.is_entrance

    def set_is_return(self, bool_value):
        self.is_return = bool_value

    def is_return_value(self):
        return self.is_return

    def set_file_name(self, filename):
        self.filename = filename

    def get_file_name(self) -> str:
        return self.filename

    def set_node_full_name(self, node_full_name):
        self.node_full_name = node_full_name

    def get_node_full_name(self):
        return self.node_full_name

    def set_name(self, name):
        self.name = name

    def get_name(self):
        return self.name

    def set_code(self, code):
        self.code = code

    def get_code(self):
        return self.code

    def set_return_value(self, return_value):
        self.return_value = return_value

    def get_return_value(self):
        return self.return_value

    def set_the_branch(self):
        self.branch = True

    def is_branch(self):
        return self.branch

    def set_sensitive_dict(self, value):
        self.sensitive_dict = value

    def get_sensitive_dict(self):
        return self.sensitive_dict

    def set_sensitive_degree(self, value):
        self.sensitive_degree = value

    def get_sensitive_degree(self):
        return self.sensitive_degree

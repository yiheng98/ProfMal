from __future__ import annotations
from typing import Generator
from tree_sitter import Language, Parser, Node
import tree_sitter_javascript as tsjavascript
import re


class ASTParser:
    def __init__(self, code: str):
        self.LANGUAGE = Language(tsjavascript.language())
        self.parser = Parser(self.LANGUAGE)
        self.tree = self.parser.parse(bytes(code, "utf-8"))
        self.root = self.tree.root_node

    @staticmethod
    def children_by_type_name(node: Node, node_type: str) -> list[Node]:
        node_list = []
        for child in node.named_children:
            if child.type == node_type:
                node_list.append(child)
        return node_list

    @staticmethod
    def child_by_type_name(node: Node, node_type: str) -> Node | None:
        for child in node.named_children:
            if child.type == node_type:
                return child
        return None

    def get_arguments(self):
        arguments_query = """
            (call_expression
                function: (identifier)
                arguments: (arguments)@arguments
            )
        """
        query_result = self.query_oneshot(arguments_query)
        return query_result

    def get_identifier_in_call_expression(self):
        identifier_query_str = """
                                (call_expression
                                   function: (identifier)@identifier
                                   arguments: (arguments)
                                )
                           """
        query_res = self.query(identifier_query_str)
        identifier_list = [r[0].text.decode() for r in query_res if r[1] == 'identifier' and r[0].start_byte == 0]
        if identifier_list and len(identifier_list) > 0:
            return identifier_list[0]
        else:
            return None

    def get_identifier_property_in_call_expression(self):
        identifier_property_identifier_query_str = """
                             (call_expression
                                function: (member_expression
                                    object: (identifier)@identifier
                                    property:(property_identifier)@property_identifier
                                    )
                                arguments: (arguments)
                             )
                            """
        query_res = self.query(identifier_property_identifier_query_str)
        identifier_list = [r[0].text.decode() for r in query_res if r[1] == 'identifier' and r[0].start_byte == 0]
        property_identifier_list = [r[0].text.decode() for r in query_res if r[1] == 'property_identifier']
        if identifier_list and len(identifier_list) > 0 and property_identifier_list and len(
                property_identifier_list) > 0:
            return identifier_list[0], property_identifier_list[0]
        else:
            return None, None

    def query_oneshot(self, query_str: str) -> Node | None:
        query = self.LANGUAGE.query(query_str)
        captures = query.captures(self.root)
        query_result = None
        for capture in captures:
            query_result = capture[0]
            break
        return query_result

    def query_last_one(self, query_str: str) -> Node | None:
        query = self.LANGUAGE.query(query_str)
        captures = query.captures(self.root)
        query_result = None
        for i in range(len(captures) - 1, -1, -1):
            query_result = captures[i][0]
            break
        return query_result

    def query(self, query_str: str):
        query = self.LANGUAGE.query(query_str)
        captures = query.captures(self.root)
        return captures

    def traverse_tree(self) -> Generator[Node, None, None]:
        cursor = self.tree.walk()

        visited_children = False
        while True:
            if not visited_children:
                yield cursor.node
                if not cursor.goto_first_child():
                    visited_children = True
            elif cursor.goto_next_sibling():
                visited_children = False
            elif not cursor.goto_parent():
                break

    def find_target_node(self, current_node: Node, line_number: int, column_number: int):
        named_children_list = current_node.named_children
        if named_children_list is not None:

            # 找到行号和列号与参数相同的Node
            for named_children in named_children_list:
                start_point = named_children.start_point
                end_point = named_children.end_point
                if line_number == start_point.row and column_number == start_point.column:
                    return named_children
                elif start_point.row <= line_number <= end_point.row:
                    found_node = self.find_target_node(named_children, line_number, column_number)
                    if found_node:
                        return found_node
                else:
                    continue

            # 没找到 输入的行号可能存在问题
            return None
        else:
            return None

    def find_target_node_non_named_children(self, current_node: Node, line_number: int, column_number: int):
        result = None
        children_list = current_node.children
        if children_list is not None:
            for child in children_list:
                candidate = None
                # 如果目标行号在子节点的范围内，先递归查找其子节点中是否有更深层的匹配
                if child.start_point.row <= line_number <= child.end_point.row:
                    candidate = self.find_target_node_non_named_children(child, line_number, column_number)
                if candidate is not None:
                    # 如果在子孙中找到了匹配，则更新结果（优先返回最深的匹配）
                    result = candidate
                # 只有当子节点自身匹配且其子节点中没有更深匹配时，才更新结果
                elif child.start_point.row == line_number and child.start_point.column == column_number:
                    result = child
            return result
        else:
            return None

    def get_call_expression_loc(self, line_number: int, column_number: int):
        """
        Find the first parent of the type 'call_expression' and 'new_expression'
        """
        target_node = self.find_target_node_non_named_children(self.root, line_number, column_number)
        if target_node:
            current_node = target_node
            while current_node.type != 'program':
                if current_node.type == 'call_expression':
                    return current_node.start_point.row, current_node.start_point.column, current_node.end_point.row, \
                        current_node.end_point.column
                elif current_node.type == 'new_expression':
                    return current_node.start_point.row, current_node.start_point.column, current_node.end_point.row, \
                        current_node.end_point.column
                else:
                    current_node = current_node.parent
        else:
            return None

    def find_call_expression_by_start_end_point(self, start_line_number: int, start_column_number: int,
                                                end_line_number: int, end_column_number: int):
        target_start = (start_line_number - 1, start_column_number - 1)
        target_end = (end_line_number - 1, end_column_number - 1)
        result = None

        def traverse(node):
            nonlocal result
            if result is not None:
                return
            if node.type == "call_expression" and node.start_point == target_start and node.end_point == target_end:
                result = node
                return
            for child in node.children:
                traverse(child)

        traverse(self.tree.root_node)
        return result

    def get_property_access_loc(self, line_number: int, column_number: int):
        target_node = self.find_target_node_non_named_children(self.root, line_number, column_number)
        if target_node:
            current_node = target_node
            while current_node.type != 'program':
                if current_node.type == 'member_expression' or current_node.type == 'subscript_expression':
                    return current_node.start_point.row, current_node.start_point.column, current_node.end_point.row, \
                        current_node.end_point.column
                else:
                    current_node = current_node.parent
        else:
            return None

    @staticmethod
    def is_isolated_eval(ast_node: Node):
        """
        Judge Current AST node is isolated eval
        Args:
            ast_node: eval Node

        Returns: True | False
        """
        parent_node = ast_node.parent
        if parent_node:
            if parent_node.type == 'expression_statement':
                return True
            if parent_node.type == 'call_expression':
                return False
            if parent_node.type == 'binary_expression':
                return False
            if parent_node.type == 'variable_declarator':
                return False
            if parent_node.type == 'return_statement':
                return False
            if parent_node.type == 'assignment_expression':
                return False
            if parent_node.type == 'if_statement':
                return False
            if parent_node.type == 'while_statement':
                return False
            if parent_node.type == 'template_string':
                return False
        return True

    @staticmethod
    def find_parent_of_type(ast_node: Node, target_type: str) -> Node | None:
        """
        Recursively searches upward in the AST for the first parent with the specified type.

        Args:
            ast_node (Node): The starting AST node.
            target_type (str): The type of the parent node to search for.
        """
        parent = ast_node.parent
        while parent is not None and parent.type != 'program':
            if parent.type == target_type:
                return parent
            parent = parent.parent
        return None

    def find_first_identifier(self, ast_node: Node):

        # Check if the current node is an identifier.
        if ast_node.type == "identifier":
            return ast_node

        # Recursively search through the children.
        for child in ast_node.children:
            result = self.find_first_identifier(child)
            if result is not None:
                return result

        return None

    def find_this_scope(self, line_number: int, column_number: int):
        current_node = self.find_target_node(self.root, line_number, column_number)

        if current_node is None:
            return None

        # find the parent node of the `this`
        # 1. the parent node is object declaration
        # 2. the parent node is class
        # 3. the parent node is function declaration
        # 4. the parent node is function expression and is under assignment
        parent_node = current_node.parent
        while parent_node is not None and parent_node.type != 'program':
            if parent_node.type == 'object':
                variable_declaration_node = self.find_parent_of_type(parent_node, 'variable_declarator')
                if variable_declaration_node is not None:
                    return variable_declaration_node.named_child(0)
                else:
                    assignment_node = self.find_parent_of_type(parent_node, 'assignment_expression')
                    if assignment_node is not None:
                        return assignment_node.named_child(0)
                    else:
                        return None
            elif parent_node.type == 'function_declaration':
                return parent_node.named_child(0)
            elif parent_node.type == 'function_expression':
                object_node = self.find_parent_of_type(parent_node, 'object')
                if object_node is not None:
                    object_parent_node = object_node.parent
                    return object_parent_node.named_child(0)
                assignment_node = self.find_parent_of_type(parent_node, 'assignment_expression')
                if assignment_node is not None:
                    left_of_assignment = assignment_node.named_child(0)
                    if left_of_assignment.type != 'identifier':
                        identifier_node = self.find_first_identifier(left_of_assignment)
                        if identifier_node is not None:
                            return identifier_node
                        else:
                            return None
                    else:
                        return None

                else:
                    return None
            elif parent_node.type == 'class_declaration':
                return parent_node.named_child(0)
            else:
                parent_node = parent_node.parent

# if __name__ == "__main__":
#     code = """
# eval("console.log(require('os').hostname())");
#
# // const axios = require('axios'); // For Node.js environment
# const os = require('os');
# // URL of the API endpoint
# const url = 'https://jsonplaceholder.typicode.com/posts';
#
# // Data to send
# const data = {
#     title: 'foo',
#     body: 'bar',
#     userId: os.hostname(),
#     data1_:  process['env'](),
#     data: process.env
# };
#
#                     """
#     parser = ASTParser(code)
#     # print(parser.find_target_node_non_named_children(parser.root, 13, 20))
#     parent_node = parser.get_call_expression_loc(13, 20)
#     print(parent_node)

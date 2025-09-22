from __future__ import annotations
from npm_pipeline.classes.stack import Stack
from npm_pipeline.classes.object import Object
from npm_pipeline.classes.identifier import Identifier
from npm_pipeline.classes.this_frame import ThisFrame
from object_type_dict import FILE_LEVEL_MODULE
from ast_parser import ASTParser


class FileContext:
    def __init__(self, name, global_identifier: dict[str, Identifier], core_module_dict: dict[str, Object]):
        self.name = f"{name}::program"
        self.root = Stack(None, self.name)
        self.last_stack = self.root
        self.file_scope_object_name_list = ["module", "exports"]
        self.file_scope_object_list = []
        self.file_scope_identifier_dict = {}
        for name in self.file_scope_object_name_list:
            self.file_scope_identifier_dict[name] = Identifier(
                name=name,
                line_number=None,
                column_number=None,
                node_id=None,
                file=None,
                source_pdg=None,
                identifier_type=FILE_LEVEL_MODULE,
                identifier_cat="BUILTIN",
            )
        for name in self.file_scope_object_name_list:
            _object = Object(name=name, object_type=FILE_LEVEL_MODULE, source_pdg=None, ref_count=2)
            self.file_scope_object_list.append(_object)
            self.file_scope_identifier_dict[name].set_ref_object(_object)
        self.global_identifier_dict = global_identifier
        self.core_module_object_dict = core_module_dict
        self.this_frame_dict: list[ThisFrame] = []
        self.file_scope_this_frame = ThisFrame("module", self.name, 0, 0)

    def add_identifier(self, identifier):
        # add the identifier to the last stack
        self.last_stack.add_identifier(identifier)

    def add_object(self, _object):
        # add identifier to the last stack
        self.file_scope_object_list.append(_object)

    def delete_object(self, _object):
        # delete the object
        if _object in self.file_scope_object_list:
            self.file_scope_object_list.remove(_object)
        else:
            pass

    def get_core_module_object(self, core_module_name):
        if core_module_name in self.core_module_object_dict:
            return self.core_module_object_dict[core_module_name]

    def add_stack(self, name):
        # add a new node to the depth tree
        new_stack = Stack(self.last_stack, name)
        self.last_stack = new_stack

    def find_identifier(self, name: str, line_number: int) -> None | Identifier:
        """
        find identifier with the name given
        """
        if name is None:
            return None
        current_stack = self.last_stack
        while current_stack is not None:
            for identifier in reversed(current_stack.get_identifier_list()):
                if name == identifier.get_name():
                    if line_number and identifier.get_line_number() and line_number >= identifier.get_line_number():
                        return identifier
            # find the former context based on the full name
            current_stack = self.find_former_stack(current_stack)

        # find the name in file level module identifier
        if name in self.file_scope_identifier_dict:
            return self.file_scope_identifier_dict[name]

        # find the name in the global object
        if name in self.global_identifier_dict:
            return self.global_identifier_dict[name]

        return None

    @staticmethod
    def find_former_stack(current_stack: Stack):
        current_scope = current_stack.get_scope()
        if current_scope.endswith("::program"):
            return None

        last_colon_index = current_scope.rfind(":")
        sub_scope_nane = current_scope[:last_colon_index]

        former_stack = current_stack.get_former()
        while former_stack and not former_stack.get_scope().endswith("::program"):
            former_scope_name = former_stack.get_scope()
            if former_scope_name == sub_scope_nane:
                return former_stack
            else:
                former_stack = former_stack.get_former()
        return former_stack

    def locate_this_frame(self, file_name: str, source_code: str, line_number: int, column_number: int):
        ast_parser = ASTParser(source_code)
        this_scope = ast_parser.find_this_scope(line_number=line_number, column_number=column_number)
        if this_scope is None:
            return self.file_scope_this_frame
        else:
            scope_name = this_scope.text.decode()
            scope_line_number = this_scope.start_point.row
            scope_column_number = this_scope.start_point.column
            for frame in self.this_frame_dict:
                if scope_name == frame.get_scope_name():
                    return frame
            # crate a new this frame
            new_this_frame = ThisFrame(scope_name, file_name, scope_line_number, scope_column_number)
            self.this_frame_dict.append(new_this_frame)
            return new_this_frame

    def find_global_object(self, name: str) -> None | Object:
        """
        find the object with the name given
        """
        if name is None:
            return None

        # find the name in global or core module
        if name in self.global_identifier_dict:
            return self.global_identifier_dict[name].get_ref_object()

        return None

    def delete_last_stack(self):
        if self.last_stack != self.root:
            self.last_stack = self.last_stack.get_former()

    def function_in_stack(self, func_name):
        # the name is the function name, check recursive call
        current_node = self.last_stack
        while current_node is not None:
            if func_name == current_node.get_scope():
                return True
            current_node = current_node.get_former()
        return False

    def get_this_frame(self, scope_name):
        if scope_name in self.this_frame_dict:
            return self.this_frame_dict[scope_name]
        else:
            return None

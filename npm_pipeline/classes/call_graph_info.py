from __future__ import annotations
import os


class Function:
    def __init__(self, file, start_line, start_column, end_line, end_column):
        self.file = file
        self.start_line = start_line
        self.start_column = start_column
        self.end_line = end_line
        self.end_column = end_column


class Call:
    def __init__(self, file, start_line, start_column, end_line, end_column):
        self.file = file
        self.start_line = start_line
        self.start_column = start_column
        self.end_line = end_line
        self.end_column = end_column
        self.call_to_function = None


class CallGraph:
    def __init__(self):
        self.entries: list[str] = []
        self.files: list[str] = []

        self.functions: dict[int, Function] = {}
        self.calls: dict[int, Call] = {}
        self.call2funcs: dict[str, dict[str, Function]] = {}

    def add_entries(self, entry: str):
        self.entries.append(os.path.join("package", entry))

    def add_file(self, file: str):
        self.files.append(os.path.join("package", file))

    def add_file_from_other_call_graph(self, file: str):
        self.files.append(file)

    def add_function(
        self, function_id: int, file_index: int, start_line: int, start_column: int, end_line: int, end_column: int
    ):
        self.functions[function_id] = Function(self.files[file_index], start_line, start_column, end_line, end_column)

    def add_call(
        self, call_id: int, file_index: int, start_line: int, start_column: int, end_line: int, end_column: int
    ):
        self.calls[call_id] = Call(self.files[file_index], start_line, start_column, end_line, end_column)

    def add_call_to_function(self, call_id: int, function_id: int):
        call_entity = self.calls[call_id]
        function_entity = self.functions[function_id]
        call_entity.call_to_function = function_entity
        call_file = call_entity.file

        # judge call file is in the dict
        if call_file not in self.call2funcs:
            self.call2funcs[call_file] = {}
        loc_str = f"{call_entity.start_line}:{call_entity.start_column}:{call_entity.end_line}:{call_entity.end_column}"
        self.call2funcs[call_file][loc_str] = function_entity

    def add_call_to_function_in_dynamic(self, caller: Call, callee: Function):
        call_file = caller.file
        if call_file not in self.call2funcs:
            self.call2funcs[call_file] = {}
        loc_str = f"{caller.start_line}:{caller.start_column}:{caller.end_line}:{caller.end_column}"
        self.call2funcs[call_file][loc_str] = callee

    def add_call_to_function_dynamic(self, caller, callee):
        call_file = os.path.join("package", caller[0])
        loc_str = f"{caller[1]}:{caller[2]}:{caller[3]}:{caller[4]}"
        if call_file not in self.call2funcs:
            self.call2funcs[call_file] = {}
        function_entity = self.find_function_entity(callee)
        if function_entity is not None:
            self.call2funcs[call_file][loc_str] = function_entity

    def find_function_entity(self, function_info):
        file = os.path.join("package", function_info[0])
        start_line = function_info[1]
        start_column = function_info[2]
        end_line = function_info[3]
        end_column = function_info[4]
        for function_id, function in self.functions.items():
            if (
                function.file == file
                and function.start_line == start_line
                and function.start_column == start_column
                and function.end_line == end_line
                and function.end_column == end_column
            ):
                return function
        return None

    def get_callee(
        self, file: str, start_line: int, start_column: int, end_line: int, end_column: int
    ) -> Function | None:
        loc_str = f"{start_line}:{start_column}:{end_line}:{end_column}"
        if file in self.call2funcs and loc_str in self.call2funcs[file]:
            return self.call2funcs[file][loc_str]
        return None

    def get_files(self):
        return self.files

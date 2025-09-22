from __future__ import annotations
from npm_pipeline.classes.object import Object
from npm_pipeline.classes.identifier import Identifier
from npm_pipeline.classes.file_context import FileContext
from object_type_dict import GLOBAL_OBJECT, FUNCTION_REF, CORE_MODULE


class ProgramContext:
    def __init__(self, file_list: list[str]):
        nodejs_global_object_list = [
            "Object",
            "process",
            "global",
            "Buffer",
            "Blob",
            "console",
            "require",
            "JSON",
            "document",
            "Math",
            "Date",
            "Array",
            "String",
            "Number",
            "Boolean",
            "RegExp",
            "Symbol",
            "BigInt",
            "Promise",
            "Set",
            "Map",
            "WeakSet",
            "WeakMap",
            "Intl",
            "fetch",
            "Error",
            "TypeError",
            "ReferenceError",
            "SyntaxError",
            "RangeError",
            "EvalError",
            "TextEncoder",
        ]
        nodejs_core_module_list = [
            "assert",
            "buffer",
            "child_process",
            "cluster",
            "crypto",
            "dgram",
            "dns",
            "domain",
            "events",
            "fs",
            "fs/promises",
            "http",
            "https",
            "net",
            "os",
            "path",
            "punycode",
            "querystring",
            "readline",
            "stream",
            "string_decoder",
            "timers",
            "tls",
            "tty",
            "url",
            "util",
            "v8",
            "vm",
            "zlib",
        ]
        global_builtin_function_list = [
            "encodeURIComponent",
            "decodeURIComponent",
            "encodeURI",
            "decodeURI",
            "escape",
            "unescape",
            "parseInt",
            "parseFloat",
            "isNaN",
            "isFinite",
            "eval",
            "fetch",
            "Buffer",
            "setTimeout",
            "btoa",
        ]
        self.global_object_dict = {}
        for name in nodejs_global_object_list:
            global_object = Object(name=name, object_type=GLOBAL_OBJECT, source_pdg=None, ref_count=1)
            self.global_object_dict[name] = global_object
        self.core_module_object_dict = {}
        for name in nodejs_core_module_list:
            core_module = Object(name=name, object_type=CORE_MODULE, source_pdg=None, ref_count=1)
            self.core_module_object_dict[name] = core_module
        self.builtin_function_object_dict = {}
        for name in global_builtin_function_list:
            builtin_function = Object(name=name, object_type=FUNCTION_REF, source_pdg=None, ref_count=1)
            self.builtin_function_object_dict[name] = builtin_function

        self.global_identifier_dict = {}
        for name, item in self.global_object_dict.items():
            # it is the dummy identifier, in order to keep the find logic general
            identifier = Identifier(
                name=name,
                line_number=None,
                column_number=None,
                node_id=None,
                file=None,
                source_pdg=None,
                identifier_type=GLOBAL_OBJECT,
                identifier_cat="BUILTIN",
            )
            identifier.set_ref_object(item)
            self.global_identifier_dict[name] = identifier

        for name, item in self.builtin_function_object_dict.items():
            # it is the dummy identifier, in order to keep the find logic general
            identifier = Identifier(
                name=name,
                line_number=None,
                column_number=None,
                node_id=None,
                file=None,
                source_pdg=None,
                identifier_type=GLOBAL_OBJECT,
                identifier_cat="FUNCTION_REF",
            )
            identifier.set_ref_object(item)
            self.global_identifier_dict[name] = identifier

        self.file_context_tree = {}
        for file in file_list:
            self.file_context_tree[file] = FileContext(file, self.global_identifier_dict, self.core_module_object_dict)

    def get_file_context(self, file_name: str) -> FileContext | None:
        if file_name in self.file_context_tree:
            return self.file_context_tree[file_name]
        else:
            return None

    def get_global_object_list(self):
        return list(self.global_object_dict.values())

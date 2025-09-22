from __future__ import annotations
from npm_pipeline.classes.object import Object
from npm_pipeline.classes.identifier import Identifier


class ThisFrame:
    def __init__(self, scope_name, scope_file, scope_start_line: int, scope_strat_column: int):
        self.scope_name = scope_name  # the name of the `this` scope
        self.scope_file = scope_file  # the file of the `this` scope
        self.scope_start_line = scope_start_line  # start line
        self.scope_strat_column = scope_strat_column  # end line
        self.this_object = Object("this", "THIS_OBJECT", None)
        self.parent_frame = None

    def get_this_object(self):
        return self.this_object

    def get_scope_name(self):
        return self.scope_name

    def get_scope_line(self):
        return self.scope_start_line

    def get_scope_column(self):
        return self.scope_strat_column

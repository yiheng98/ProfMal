from __future__ import annotations
from base_classes.pdg import PDG
from npm_pipeline.classes.object import Object


class Identifier:
    def __init__(
        self,
        name,
        line_number,
        column_number,
        node_id,
        file,
        source_pdg: int | None,
        identifier_type,
        identifier_cat=None,
    ):
        self.node_id = node_id  # Corresponding node ID in PDG
        self.identifier_type = identifier_type  # the type of the identifier
        self.name = name  # Name of the identifier
        self.line_number = line_number  # line number
        self.column_number = column_number  # column number
        self.file = file
        self.source_pdg = source_pdg  # Which PDG this belongs to
        self.ref_object: Object | None = None  # bind the identifier to the object

    def get_name(self):
        return self.name

    def get_line_number(self) -> int:
        return self.line_number

    def get_column_number(self) -> int:
        return self.column_number

    def get_node_id(self):
        return self.node_id

    def get_file(self):
        return self.file

    def get_pdg(self) -> int:
        return self.source_pdg

    def set_ref_object(self, bind_object: Object):
        if self.ref_object is not None:
            self.ref_object.subtract_ref_count()
        self.ref_object = bind_object
        self.ref_object.add_ref_count()

    def get_ref_object(self) -> Object:
        return self.ref_object

    def get_identifier_type(self):
        return self.identifier_type

    def set_identifier_type(self, identifier_type):
        self.identifier_type = identifier_type

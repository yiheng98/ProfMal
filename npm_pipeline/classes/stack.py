from npm_pipeline.classes.identifier import Identifier
import copy


class Stack:
    def __init__(self, former, scope):
        self.former = former
        self.scope = scope
        self.identifier_list: list[Identifier] = []

    def __deepcopy__(self, memo):
        new_node = Stack(copy.deepcopy(self.former, memo), self.scope)
        new_node.identifier_list = copy.deepcopy(self.identifier_list, memo)
        return new_node

    def get_former(self):
        return self.former

    def get_identifier_list(self):
        return self.identifier_list

    def add_identifier(self, identifier):
        self.identifier_list.append(identifier)

    def get_scope(self):
        return self.scope

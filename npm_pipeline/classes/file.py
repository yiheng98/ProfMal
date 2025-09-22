class Function:
    def __init__(self, function_name):
        self.name = function_name
        self.visited = False


class File:
    def __init__(self, filename, raw_code):
        self.filename = filename
        self.function_list: list[Function] = []
        self.raw_code: list[str] = raw_code

    def add_function(self, function_name):
        self.function_list.append(Function(function_name))

    def get_raw_code(self) -> list[str]:
        return self.raw_code

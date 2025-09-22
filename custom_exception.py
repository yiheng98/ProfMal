class PackageJsonNotFoundException(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg


class JoernGenerationException(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg


class GraphReadingException(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg


class JellyCallGraphGenerationError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg


class DynamicRunningException(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg


class JoernGenerationExceptionInDynamic(Exception):
    def __init__(self, msg, api_call_info=None):
        self.msg = msg
        self.api_call_info = api_call_info

    def __str__(self):
        return self.msg


class DynamicCallGraphEmptyException(Exception):
    def __init__(self, msg, api_call_info=None):
        self.msg = msg
        self.api_call_info = api_call_info

    def __str__(self):
        return self.msg


class NoEntryScriptException(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg

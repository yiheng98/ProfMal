class Script:
    def __init__(self, phase):
        self.phase = phase
        self.static = False
        self.script_type = None
        self.files = []
        self.packages = []
        self.shell_command = None
        self.shell_command_description = ""
        self.malicious = False

    def set_script_type(self, script_type):
        self.script_type = script_type

    def get_script_type(self):
        return self.script_type

    def set_running_files(self, files: list[str]):
        self.files = files

    def get_running_files(self):
        return self.files

    def set_packages(self, downloads: list[str]):
        self.packages = downloads

    def get_packages(self):
        return self.packages

    def set_shell_command(self, shell_command):
        self.shell_command = shell_command

    def get_shell_command(self):
        return self.shell_command

    def set_shell_command_description(self, description):
        self.shell_command_description = description

    def get_shell_command_description(self):
        return self.shell_command_description

    def set_need_static(self, bool_value):
        self.static = bool_value

    def need_static(self):
        return self.static

    def set_malicious(self, bool_value):
        self.malicious = bool_value

    def is_malicious(self):
        return self.malicious

    def to_dict(self):
        return {
            "phase": self.phase,
            "static": self.static,
            "script_type": self.script_type,
            "files": self.files,
            "downloads": self.packages,
            "shell_command": self.shell_command,
            "shell_command_description": self.shell_command_description,
            "malicious": self.malicious,
        }

    def to_dict_npm(self):
        return {"downloads": self.packages}

    def to_dict_node(self):
        return {
            "files": self.files,
        }

    def to_dict_shell_command(self):
        return_value = {
            "shell_command": self.shell_command,
            "shell_command_description": self.shell_command_description,
        }
        if self.files:
            return_value["files"] = self.files
        if self.packages:
            return_value["downloads"] = self.packages
        return return_value

    @classmethod
    def from_dict(cls, data):
        script = cls(data["phase"])
        script.static = data["static"]
        script.script_type = data["script_type"]
        script.files = data["files"]
        script.packages = data["downloads"]
        script.shell_command = data["shell_command"]
        script.shell_command_description = data["shell_command_description"]
        script.malicious = data["malicious"]
        return script

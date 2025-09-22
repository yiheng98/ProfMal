import json
import re
import llm as llm
from loguru import logger


class PackageJson:
    def __init__(self, package_json_path):
        self.package_json_path = package_json_path
        self.main = None  # main script
        self.preinstall = None  # preinstall script
        self.install = None  # install script
        self.postinstall = None  # postinstall script
        self.malicious_script = []
        self.install_time_script = set()
        self.bin = set()
        self.set_metadata()
        self.set_install_time_script()

    def get_main(self):
        return self.main

    def get_install_script(self):
        return self.install_time_script

    def get_bin_scrip(self):
        return self.bin

    def set_metadata(self):
        with open(self.package_json_path, "r") as package_json_file:
            package_json_data = json.load(package_json_file)

        if "main" in package_json_data.keys():
            self.main = package_json_data["main"]
            if not (self.main.endswith(".js") or self.main.endswith(".mjs") or self.main.endswith(".cjs")):
                self.main = self.main + ".js"
        else:
            # default index.js
            self.main = "index.js"

        if "scripts" in package_json_data.keys():
            # search for entries in scripts
            for key, value in package_json_data["scripts"].items():
                # check the installation script
                # get the "preinstall" script
                if key == "preinstall":
                    self.preinstall = value
                elif key == "install":
                    self.install = value
                elif key == "postinstall":
                    self.postinstall = value
                else:
                    pass

        if "bin" in package_json_data:
            bin_value = package_json_data["bin"]
            if isinstance(bin_value, str):
                self.bin.add(bin_value)
            else:
                for key, value in bin_value.items():
                    self.bin.add(value)

    def set_install_time_script(self):
        if self.preinstall:
            self.install_time_script.update(self.script_regex_extract(self.preinstall))
        if self.install:
            self.install_time_script.update(self.script_regex_extract(self.install))
        if self.postinstall:
            self.install_time_script.update(self.script_regex_extract(self.postinstall))

    @staticmethod
    def script_regex_extract(script):
        pattern_node = r"node\s+([^\s]+(?:\.js|\.mjs|\.cjs)\b(?:\s+[^\s]+(?:\.js|\.mjs|\.cjs)\b)*)"
        script_file = set()

        match = re.findall(pattern_node, script)
        if len(match) > 0:
            for script in match:
                script_file.add(script)

        return script_file

    def malicious_script_analysis(self):
        if self.preinstall:
            if self.judge_maliciousness(self.preinstall):
                self.malicious_script.append(self.preinstall)
        if self.install:
            if self.judge_maliciousness(self.install):
                self.malicious_script.append(self.install)
        if self.postinstall:
            if self.judge_maliciousness(self.postinstall):
                self.malicious_script.append(self.postinstall)

        return self.malicious_script

    def judge_maliciousness(self, script):
        try:
            res = llm.llm_shell_command_interpret(script)
        except Exception as e:
            logger.warning(f"Shell Command Exception: {e}")
            res = 0
        if res > 0.5:
            return True
        else:
            return False

import json
import os


class Report:
    def __init__(self):
        self.is_malicious = False
        self.maliciousness_in_package_json = False
        self.maliciousness_in_code = False
        self.install_time_script = []  # Script execution during installation
        self.malicious_script_in_static = []  # Malicious scripts detected by static analysis
        self.malicious_script_in_dynamic = []  # Malicious scripts detected by dynamic analysis

    def set_malicious(self, malicious: bool):
        self.is_malicious = malicious

    def add_install_time_script(self, script):
        self.install_time_script.append(script)

    def add_malicious_script_to_static(self, script):
        self.malicious_script_in_static.append(script)

    def add_malicious_script_to_dynamic(self, script):
        self.malicious_script_in_dynamic.append(script)

    def get_malicious(self) -> bool:
        return self.is_malicious

    def set_maliciousness_in_package_json(self):
        self.maliciousness_in_package_json = True
        self.is_malicious = True

    def is_maliciousness_in_package_json(self):
        return self.maliciousness_in_package_json

    def set_maliciousness_in_code(self):
        self.maliciousness_in_code = True
        self.is_malicious = True

    def is_maliciousness_in_code(self):
        return self.maliciousness_in_code

    def get_install_time_scripts(self):
        return self.install_time_script

    def get_malicious_scripts_in_static(self):
        return self.malicious_script_in_static

    def get_malicious_scripts_in_dynamic(self):
        return self.malicious_script_in_dynamic

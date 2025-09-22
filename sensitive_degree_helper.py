import re
import llm
import json


def is_sensitive_path(path: str) -> bool:
    """
    Returns True if the input path contains any of the sensitive keywords,
    otherwise returns False.
    """
    # List of regex patterns for sensitive keywords.
    sensitive_patterns = [
        r"/etc/issue",  # /etc/issue
        r"/etc/motd",  # /etc/motd
        r"/etc/passwd",  # /etc/passwd
        r"/etc/group",  # /etc/group
        r"/etc/resolv\.conf",  # /etc/resolv.conf
        r"/etc/shadow",  # /etc/shadow
        r"/etc/mtab",  # /etc/mtab
        r"/etc/inetd\.conf",  # /etc/inetd.conf
        r"/var/log/dmessage",  # /var/log/dmessage
        r"authorized_keys",  # authorized_keys anywhere in the path
        r"id_rsa(?:\.keystore|\.pub)?",  # id_rsa, id_rsa.keystore, or id_rsa.pub anywhere in the path
        r"known_hosts",  # known_hosts anywhere in the path
        r"/etc/httpd/logs/access_log",  # /etc/httpd/logs/access_log
        r"/etc/httpd/logs/error_log",  # /etc/httpd/logs/error_log
        r"/var/www/logs/access_log",  # /var/www/logs/access_log
        r"/var/www/logs/access\.log",  # /var/www/logs/access.log
        r"/usr/local/apache/logs/access(?:_log|\.log)",  # /usr/local/apache/logs/access_log or access.log
        r"/var/log/apache(?:2)?/access(?:_log|\.log)",  # Apache access logs in /var/log/apache or /var/log/apache2
        r"/var/log/access_log",  # /var/log/access_log
        r"\.bashrc",  # .bashrc anywhere
        r"\.zshrc",  # .zshrc anywhere
        r"\.zsh_history",  # .zsh_history anywhere
        r"\.mysql_history",  # .mysql_history anywhere
        r"\.my\.cnf",  # .my.cnf anywhere
        # For .bash_history and .profile, ensure the filename is exactly one of these (ignoring any directory path)
        r"(?:/|^)(\.bash_history|\.profile)$",
    ]

    # Check each pattern to see if it exists anywhere in the given path.
    for pattern in sensitive_patterns:
        if re.search(pattern, path):
            return True
    return False


def get_subprocess_sensitivity_degree(full_name: str, parameters: str):
    if parameters:
        if full_name in ["child_process.execFile", "child_process.execFileSync"]:
            degree = llm.llm_execute_file_interpret(parameters)
        else:
            degree = llm.llm_shell_command_interpret(parameters)
        return degree
    else:
        return 0.5


def get_file_sensitivity_degree(full_name: str, parameters: str, return_value):
    if parameters:
        result = str(return_value)
        if full_name in [
            "fs.createReadStream",
            "fs.createWriteStream",
            "fs.open",
            "fs/promises.open",
            "fs.openSync",
            "fs.readLink",
            "fs/promises.readlink",
            "fs.readlinkSync",
        ]:
            if is_sensitive_path(parameters):
                return 1.0
            else:
                return llm.llm_path_sensitivity_interpret(parameters)
        elif full_name in ["fs.glob", "fs.globSync", "fs/promises.glob"]:
            return llm.llm_file_pattern_sensitivity_interpret(parameters)
        elif full_name in ["fs.readdirSync", "fs.readdir", "fs/promises.readdir"]:
            if is_sensitive_path(parameters):
                return 1.0
            else:
                return llm.llm_dir_sensitivity_interpret(parameters)
        elif full_name in ["fs.rm", "fs/promises.rm", "fs.rmSync", "fs.unlink", "fs.unlinkSync", "fs/promises.unlink"]:
            if is_sensitive_path(parameters):
                return 1.0
            else:
                return llm.llm_rm_files_sensitivity_interpret(parameters)
        elif full_name in [
            "fs.appendFile",
            "fs.appendFileSync",
            "fs/promises.appendFile",
            "fs.writeFile",
            "fs.writeFileSync",
            "fs/promises.writeFile",
        ]:
            try:
                parsed_parameters = json.loads(parameters)
                if isinstance(parsed_parameters, dict):
                    path = parsed_parameters.get("path", "")
                    data = parsed_parameters.get("data", "")
                    return llm.llm_file_writing_sensitivity_interpret(path, data)
            except json.JSONDecodeError:
                return 0.5
        elif full_name in ["fs.readFile", "fs/promises.readFile", "fs.readFileSync"]:
            return llm.llm_file_reading_sensitivity_interpret(parameters, result)
        elif full_name in ["fs.exists", "fs.existsSync"]:
            return llm.llm_path_sensitivity_interpret(parameters)
        else:
            return 0.5
    else:
        return 0.5

from openai import OpenAI
import yaml
import time
from loguru import logger
import tiktoken

with open("./config.yaml", "r") as file:
    config = yaml.safe_load(file)

model_name = config["LLM"]
api_key = config["API_KEY"]
enc = tiktoken.get_encoding("cl100k_base")


def llm_shell_command_interpret(shell_command):
    messages = [
        {
            "role": "system",
            "content": """
            You're a security expert with extensive experience in Linux shell programming and security risk assessment. You will receive one input:
            Shell Command: A string representing a Linux shell command.
            Your task is to evaluate the degree of sensitivity (i.e., the potential maliciousness) of the provided shell command based on its behavior. Based on your expert analysis, assign a sensitivity score as a floating-point number in the range [0, 1] according to the following guidelines:
             Sensitivity Scoring:
             0: Not sensitive at all.
             0 to 0.5: Low sensitivity (act as a warning).
             0.5 to 1: High sensitivity (should be closely scrutinized).
             1: Absolutely sensitive.
            
            Only report higher score if you are confident of the result.
            Guidelines for Analysis:
            1. Data Exfiltration: If the command retrieves local data, such as user or system information (e.g., passwords, system logs), and sends it externally (e.g., to a remote server via URL, DNS lookup, or other network protocols), assign a score near 1. Additionally, if the command displays sensitive data, such as passwords or system files (e.g., contents of /etc/passwd), even without sending it externally, this should also be considered severe and assigned a high score, reflecting the potential for exploitation or information leakage.
            2. Execution of Scripts or Binaries: If the command executes shell scripts (.sh), batch files (.bat), or other executable binaries (.exe), assign a score near 1.
            3. File Download without Execution: If the command downloads files but does not execute them, assign a score near 0.
            4. Unusual URL Interaction: If the command interacts with suspicious or unusual URLs, assign a score near 1. This includes URLs with suspicious patterns such as excessive hyphens, random strings, or encoded characters, URLs from domains known for hosting malicious content, unusual network communication patterns using non-standard ports or suspicious protocols, URLs that bypass normal DNS resolution or use IP addresses directly, and any URL interaction that appears designed to evade detection.
            5. Dropper Behavior: If the command exhibits dropper characteristics designed to deliver additional malicious payloads, assign a score of 1. This includes downloading and staging malicious payloads from remote servers, establishing communication channels for multi-stage payload delivery, creating persistence mechanisms for ongoing payload retrieval, using various network protocols (HTTP, DNS, ICMP) to fetch additional malware, and commands that facilitate the download and execution of secondary malicious components.
            6. Download and Execute: If the command both downloads and executes files, assign a score near 1.
            7. Tampering Critical Files: If the command modifies or injects entries into startup or security-sensitive files, such as crontab, /etc/rc.local, systemd unit files, user shell profiles (e.g., ~/.bashrc, ~/.profile), /etc/shadow, or ~/.ssh/authorized_keys, assign a score near 1.
            8. Process Injection: If the command leverages techniques to inject or hijack execution within another process, e.g., using ptrace (via gdb, strace -p), LD_PRELOAD tricks, dlopen/dlsym, shared memory manipulation, or calling debuggers to manipulate a running binary, assign a score near 1.
            9. Data Obfuscation and Encoding: If the command applies transformations to payloads or exfiltrated data, such as base64 encoding/decoding, hex encoding, URL encoding, compression, or encryption to hide malicious content, assign a score near 1.
            10. NPM Package Download: If the command downloads a legitimate third-party NPM package, assign a risk score near 0; however, if the package name exhibits signs of typosquatting or contains other unusual naming patterns, assign a score near 1.
            11. Reverse Shell Initiation: If the command initiates a reverse shell, assign a score of 1.
            12. Deletion of Unimportant Files: If the command deletes only non-critical files (e.g., temporary files), assign a score near 0.
            13. System Shutdown: If the command shuts down the system, assign a score near 1.
            14. Deletion of Uncritical Files: If the command only deletes files in non-critical directories such as dist, temp, cache, or node_modules, its risk score should be set close to 0, ensuring that only deletion operations involving system or critical user paths are strictly evaluated.
            15. Deletion of Critical Files: If the command deletes important files (such as user files, system files, or root), assign a score near 1.
            16. Resource Exhaustion: If the command is used to exhaust system resources, such as CPU (fork bombs, infinite loops), memory (memory allocation attacks), disk space (file system flooding), or network bandwidth, assign a score near 1.
            17. Local JavaScript Execution Only: If the command solely runs a local JavaScript file (e.g., .js, .cjs, .mjs files) without any additional risky operations, assign a score near 0.
            18. Non-Typical Node Execution: If the command attempts to run a file with a non-standard extension for Node (e.g., "node note.md"), assign a score near 1.
            19. Non-Malicious Shell Command: If the command does not show any maliciousness, assign a score 0. 
            20. Invalid Shell Command: If the command is not a valid Linux shell command, assign a score near 0.
            If none of the above criteria clearly apply, use your expert judgment to assign a sensitivity score between 0 and 1.
            
            Return only the final sensitivity score (a floating-point number between 0 and 1) as the output, with no additional explanation or text.
            """,
        },
        {"role": "user", "content": f"""Shell Command: {shell_command}"""},
    ]
    logger.info(f"[LLM] Analyse the shell Command\n {shell_command}")
    try:
        answer = connect_with_retry(messages)
    except ConnectionError:
        answer = 0.5
    try:
        answer_flow = float(answer)
    except ValueError:
        logger.warning(f"[LLM] The return value is not a valid floating-point number: {answer}")
        answer_flow = 0.5
    logger.info(f"[LLM] The Degree of the Shell Command Sensitivity is: {answer_flow}")
    answer_flow = max(0.0, min(answer_flow, 1.0))
    return answer_flow


def llm_file_reading_sensitivity_interpret(file_path: str, content: str):
    messages = [
        {
            "role": "system",
            "content": """
               You're a security expert specializing in NPM package analysis and file system security. You are provided with two inputs:
               1. File Path: A string representing the Linux file system path where data is being read by file reading APIs (such as fs.readFile, fs.readFileSync, etc.).
               2. File Content: The actual content read from the file through the file reading API.
               Your task is to analyze both the file path parameter and the actual file content to determine the sensitivity of the file reading behavior in the context of NPM packages and Node.js applications. Based on your expert analysis, assign a sensitivity score as a floating-point number in the range [0, 1] according to the following guidelines:
               Sensitivity Scoring:
                0: Not sensitive at all.
                0 to 0.5: Low sensitivity (act as a warning).
                0.5 to 1: High sensitivity (should be closely scrutinized).
                1: Absolutely sensitive.
                
                Only report higher score if you are confident of the result.
                Here are the cases for the analysis of the degree of sensitivity:
                Path-Based Sensitivity:
                1. Environment and Configuration Files: Files such as .env, .env.local, .env.production, or any file containing sensitive environment variables, API keys, database credentials, or application configurations, assign a score near 1.
                2. Authentication and Security Files: Files like .netrc, .htpasswd, keystore files, or any file with "password", "auth", "token", "secret", "credential" in its name or path typically store sensitive authentication data, assign a score near 1.
                3. SSH and Cryptographic Key Files: Files in directories like .ssh, .gnupg, or with names containing "key", "cert", "pem", "p12", "pfx" should be scrutinized for private keys, certificates, or cryptographic material, assign a score near 1.
                4. System Configuration and Network Settings Files: Files such as /etc/sysctl.conf, /etc/network/interfaces, /etc/resolv.conf, /etc/hosts, or system-level configurations for kernel parameters, network interfaces, and DNS settings. These files are critical to system operation and could be targeted for tampering or reconnaissance, assign a score near 1.
                5. Shell Configuration and History Files: Files such as .bashrc, .zshrc, .bash_history, .zsh_history, .profile, or shell configuration files that may contain command histories, aliases, or environment variables exposing sensitive information, assign a score near 1.
                6. Database and Cache Files: Files with extensions like .db, .sqlite, .sql, .dump, .backup, or located in database directories (mysql, postgresql, mongodb, redis) that may contain sensitive application data, user information, or database credentials, assign a score near 1.
                7. Cryptocurrency Wallet Files: Files related to cryptocurrency wallets in directories like .bitcoin, .ethereum, or other blockchain-related directories, as well as files with extensions like .dat, .json, .wallet containing private keys, seed phrases, or wallet configurations, assign a score near 1.
                8. Log and Temporary Files: Files in /tmp, /var/log, or with extensions like .log, .tmp that might contain sensitive information, debugging data, or temporary credentials depending on the application context, assign a score between 0.3-0.7 based on content.
                9. Application-Specific Sensitive Files: Files like docker-compose.yml, Dockerfile, kubernetes manifests, CI/CD configuration files (.github/workflows, .gitlab-ci.yml, jenkins files) that may contain deployment secrets or infrastructure details, assign a score near 1.
                10. Browser and Application Data: Files in browser profile directories, application data directories, or files containing cookies, session data, stored passwords, or user preferences that could expose personal information, assign a score near 1.
                11. Other Cases: Consider any file that may hold configuration settings, API endpoints, database connection strings, certificates, or other credentials that could be exploited by malicious actors.
                
                Content-Based Analysis:
                1. Authentication Credentials: Presence of usernames, passwords, authentication tokens, API keys, OAuth tokens, JWT tokens, session IDs, or other secret authentication data. Look for patterns like "password=", "token:", "api_key", "secret_key", "auth_token", assign a score near 1.
                2. Cryptographic Material: Private keys (RSA, ECDSA, Ed25519), certificates, encoded strings resembling cryptographic data (base64 encoded keys), PGP keys, SSL certificates, or any cryptographic signatures and hashes, assign a score near 1.
                3. Database and Connection Strings: Database connection strings, SQL queries with sensitive data, database credentials, connection URLs containing usernames/passwords, MongoDB connection strings, Redis auth strings, assign a score near 1.
                4. Network and Infrastructure Configuration: Server configurations, network topology information, IP addresses, port configurations, firewall rules, proxy settings, VPN configurations, or infrastructure details that could aid in reconnaissance, assign a score near 1.
                5. Personal and User Data: Personal identifiable information (PII), email addresses, phone numbers, addresses, social security numbers, credit card information, user profiles, or any data that could compromise user privacy, assign a score near 1.
                6. Application Secrets and Configuration: Application-specific secrets, feature flags with sensitive settings, internal API endpoints, service discovery configurations, microservice communication keys, or deployment-specific configurations, assign a score near 1.
                7. Financial and Payment Information: Payment gateway configurations, merchant IDs, payment tokens, cryptocurrency wallet addresses, financial API credentials, banking information, or transaction details, assign a score near 1.
                8. Source Code and Intellectual Property: Proprietary algorithms, business logic, internal code comments revealing sensitive information, hardcoded secrets in source code, or intellectual property that should not be exposed, assign a score between 0.5-1 based on sensitivity.
                9. Log and Debug Information: Error logs containing stack traces with sensitive paths, debug information revealing internal system details, performance metrics exposing system architecture, or diagnostic data that could aid attackers, assign a score between 0.3-0.8 based on content.
                10. Encoded or Obfuscated Data: Base64 encoded content that might contain sensitive information, encrypted data with visible keys or hints, serialized objects containing credentials, or any obfuscated content that requires further analysis, assign a score between 0.5-1 based on context.
                
                If the file path does not clearly indicate sensitivity, use the file content to adjust the sensitivity score accordingly. Ensure your final judgment is based on expert security knowledge.
                Return only the final sensitivity score (a floating-point number between 0 and 1) as the output, with no additional explanation or text.
                """,
        },
        {
            "role": "user",
            "content": f"""File Path: {file_path}\nFile Content: {content}""",
        },
    ]

    logger.info(f"[LLM] Analyse the Degree of the File Reading Sensitivity\nFile Path: {file_path}\nContent: {content}")
    if max_token(content):
        logger.info("[LLM] Max Token, the degree of the File Reading Sensitivity is: 1")
        return 1.0
    try:
        answer = connect_with_retry(messages)
    except ConnectionError:
        answer = 0.5
    try:
        answer_flow = float(answer)
    except ValueError:
        logger.warning(f"[LLM] The return value is not a valid floating-point number: {answer}")
        answer_flow = 0.5
    logger.info(f"[LLM] The Degree of the File Reading Sensitivity is: {answer}")
    answer_flow = max(0.0, min(answer_flow, 1.0))
    return answer_flow


def llm_file_writing_sensitivity_interpret(file_path: str, content: str):
    messages = [
        {
            "role": "system",
            "content": """
                  You're a security expert specializing in NPM package analysis and file system security. You are provided with two inputs:
                  1. File Path: A string representing the Linux file system path where data is being written by file writing APIs (such as fs.writeFile, fs.writeFileSync, fs.appendFile, etc.).
                  2. File Content: The actual content that is intended to be written to the file through the file writing API.
                  Your task is to analyze both the file path parameter and the actual file content to determine the sensitivity of the file writing behavior in the context of NPM packages and Node.js applications. Based on your expert analysis, assign a sensitivity score as a floating-point number in the range [0, 1] according to the following guidelines:
                  Sensitivity Scoring:
                  0: Not sensitive at all.
                  0 to 0.5: Low sensitivity (act as a warning).
                  0.5 to 1: High sensitivity (should be closely scrutinized).
                  1: Absolutely sensitive.
                  
                  Only report higher score if you are confident of the result.
                  Here are the cases for the analysis of the degree of sensitivity:
                   Path-Based Sensitivity:
                   1. System and Critical Configuration Files: Writing to files in system directories such as /etc, /var, /usr, /boot, or any file that is part of core system configurations (e.g., /etc/passwd, /etc/shadow, /etc/ssh/sshd_config, /etc/sudoers, /etc/crontab) should be flagged as highly sensitive due to potential system compromise, assign a score near 1.
                   2. Startup and Persistence Files: Writing to startup directories, autostart files, system service files, or persistence mechanisms (e.g., /etc/rc.local, ~/.config/autostart/, systemd unit files) that could establish malware persistence, assign a score near 1.
                   3. User Configuration and History Files: Writing to user-specific configuration files like ~/.bashrc, ~/.zshrc, ~/.profile, history files like ~/.bash_history, ~/.zsh_history, or user preference files that could modify user environment or expose command histories, assign a score near 1.
                   4. SSH and Cryptographic Key Files: Writing to directories like .ssh, .gnupg, or files with names containing "key", "cert", "pem", "p12", "pfx", "keystore" that could compromise cryptographic security or enable unauthorized access, assign a score near 1.
                   5. Environment and Configuration Files: Writing to .env, .env.local, .env.production, or any file containing environment variables, API keys, database credentials, or application configurations that could expose sensitive settings, assign a score near 1.
                   6. Authentication and Security Files: Writing to files like .netrc, .htpasswd, keystore files, or any file with "password", "auth", "token", "secret", "credential" in its name or path that could store or modify authentication data, assign a score near 1.
                   7. Database and Data Files: Writing to files with extensions like .db, .sqlite, .sql, .dump, .backup, or located in database directories (mysql, postgresql, mongodb, redis) that could corrupt data, inject malicious content, or modify database configurations, assign a score near 1.
                   8. Web Server and Application Files: Writing to web server document roots, configuration files (apache, nginx, IIS), application deployment files, or web application source code that could enable web-based attacks or modify application behavior, assign a score near 1.
                   9. Executable and Script Files: Writing to executable files (.exe, .bat, .sh, .ps1, .py, .js in executable contexts), binary files, or files in executable directories (/usr/bin, /usr/local/bin) that could introduce malicious code execution, assign a score near 1.
                   10. Log and Monitoring Files: Writing to system logs, application logs, audit files, or monitoring configurations that could hide malicious activities, tamper with evidence, or disable security monitoring, assign a score between 0.7-1 based on the log type and content.
                   11. Backup and Recovery Files: Writing to backup directories, recovery files, or system restore points that could compromise data integrity or recovery capabilities, assign a score near 1.
                   12. Network and Firewall Configuration: Writing to network configuration files, firewall rules, proxy settings, or DNS configurations that could modify network security or enable network-based attacks, assign a score near 1.
                   13. Application-Specific Sensitive Files: Writing to Docker files, Kubernetes manifests, CI/CD configuration files (.github/workflows, .gitlab-ci.yml, jenkins files), deployment scripts that could compromise deployment security or infrastructure, assign a score near 1.
                   14. Browser and Application Data: Writing to browser profile directories, application data directories, or files containing cookies, session data, stored passwords, or user preferences that could compromise user privacy or enable session hijacking, assign a score near 1.
                   15. Temporary and Cache Files: Writing to /tmp, /var/tmp, cache directories, or temporary files that might be used to stage malicious content or bypass security controls, assign a score between 0.3-0.7 based on content and location.
                   16. Other Critical Considerations: Evaluate any other files that could potentially hold sensitive information, modify system behavior, or be used for malicious purposes, such as certificate files, license files with embedded credentials, or application-specific configuration files.
                   
                   Content-Based Analysis:
                   1. Malicious Code and Scripts: Content containing executable code, shell commands, Python scripts, or any scripting language that could execute malicious operations when the file is later executed or sourced, assign a score near 1.
                   2. Authentication Credentials: Content containing usernames, passwords, authentication tokens, API keys, OAuth tokens, JWT tokens, session IDs, or other secret authentication data. Look for patterns like "password=", "token:", "api_key", "secret_key", "auth_token", assign a score near 1.
                   3. Cryptographic Material: Content with private keys (RSA, ECDSA, Ed25519), certificates, PGP keys, SSL certificates, encrypted data with visible keys, cryptographic signatures, or any cryptographic material that could compromise security, assign a score near 1.
                   4. System Configuration and Commands: Content that modifies system settings, network configurations, firewall rules, system services, or contains system administration commands that could alter system behavior, assign a score near 1.
                   5. Database and Connection Strings: Content with database connection strings, SQL queries, database credentials, connection URLs containing usernames/passwords, MongoDB connection strings, Redis auth strings, or database manipulation commands, assign a score near 1.
                   6. Network and Infrastructure Data: Content containing server configurations, network topology information, IP addresses, port configurations, proxy settings, VPN configurations, DNS settings, or infrastructure details that could aid in attacks, assign a score near 1.
                   7. Personal and Sensitive Data: Content with personal identifiable information (PII), email addresses, phone numbers, addresses, social security numbers, credit card information, user profiles, or any data that could compromise user privacy, assign a score near 1.
                   8. Application Secrets and Configuration: Content with application-specific secrets, feature flags with sensitive settings, internal API endpoints, service discovery configurations, microservice communication keys, or deployment-specific configurations, assign a score near 1.
                   9. Financial and Payment Information: Content with payment gateway configurations, merchant IDs, payment tokens, cryptocurrency wallet addresses, financial API credentials, banking information, or transaction details, assign a score near 1.
                   10. Persistence and Backdoor Mechanisms: Content that establishes persistence mechanisms, creates backdoors, modifies startup processes, installs services, or creates scheduled tasks that could maintain unauthorized access, assign a score near 1.
                   11. Data Exfiltration Payloads: Content designed to collect, package, or transmit sensitive data, including data harvesting scripts, compression utilities for sensitive files, or network transmission code, assign a score near 1.
                   12. Obfuscated or Encoded Content: Content that appears obfuscated, base64 encoded, hex encoded, or otherwise disguised to hide its true purpose, especially if it decodes to suspicious content, assign a score between 0.7-1 based on the decoded content.
                   13. Log Tampering and Anti-Forensics: Content designed to clear logs, modify timestamps, delete evidence, or interfere with security monitoring and forensic analysis, assign a score near 1.
                   14. Exploit Code and Vulnerabilities: Content containing exploit code, vulnerability triggers, buffer overflow attempts, injection payloads (SQL, XSS, command injection), or any code designed to exploit system vulnerabilities, assign a score near 1.
                   15. Legitimate but Sensitive Content: Content that is legitimate but contains sensitive information such as source code with embedded secrets, configuration files with default passwords, or documentation revealing system architecture, assign a score between 0.5-0.8 based on sensitivity level.
                   
                   If the file path does not clearly indicate sensitivity, use the file content to adjust the sensitivity score accordingly. Ensure your final judgment is based on expert security knowledge.
                   
                   Return only the final sensitivity score (a floating-point number between 0 and 1) as the output, with no additional explanation or text.
                   """,
        },
        {
            "role": "user",
            "content": f"""File Path: {file_path}\nFile Content: {content}""",
        },
    ]

    logger.info(f"[LLM] Analyse the Degree of the File Writing Sensitivity\nFile Path: {file_path}\nContent: {content}")
    if max_token(content):
        logger.info("[LLM] Max Token, the degree of the File Writing Sensitivity is: 1")
        return 1.0
    try:
        answer = connect_with_retry(messages)
    except ConnectionError:
        answer = 0.5
    try:
        answer_flow = float(answer)
    except ValueError:
        logger.warning(f"[LLM] The return value is not a valid floating-point number: {answer}")
        answer_flow = 0.5
    logger.info(f"[LLM] The Degree of the File Writing Sensitivity is: {answer}")
    answer_flow = max(0.0, min(answer_flow, 1.0))
    return answer_flow


def llm_dir_sensitivity_interpret(dir_path: str):
    messages = [
        {
            "role": "system",
            "content": """
                    You're a security expert specializing in NPM package analysis and file system security. You are provided with a directory path as input.
                    Your task is to analyze the sensitivity of the directory based on its name and location in the file system, particularly in the context of directory reading APIs (such as fs.readdir, fs.readdirSync, fs.opendir, etc.) used by NPM packages and Node.js applications. Based on your expert analysis, assign a sensitivity score as a floating-point number in the range [0, 1] according to the following guidelines:
                     Sensitivity Scoring:
                     0: Not sensitive at all.
                     0 to 0.5: Low sensitivity (act as a warning).
                     0.5 to 1: High sensitivity (should be closely scrutinized).
                     1: Absolutely sensitive.
                     
                     Only report higher score if you are confident of the result.
                     Here are the cases for the analysis of the degree of sensitivity:
                    1. System and Critical Configuration Directories: Directories like /etc, /var, /root, or containing critical system configurations (e.g., /etc/ssh, /etc/passwd, /etc/shadow) should be flagged as highly sensitive, assign a score near 1.
                    2. User Home and Configuration Directories: User home directories (~/, /home/username) or directories containing user-specific configuration files (e.g., ~/.bashrc, ~/.zshrc, .bash_history, .zsh_history) that may contain personal data or command histories, assign a score near 1.
                    3. Authentication and Security Directories: Directories like .ssh, .gnupg, or any directory containing cryptographic keys, certificates, or authentication materials, assign a score near 1.
                    4. NPM and Package Manager Directories: Directories like node_modules, .npm, .yarn, or package manager directories that may contain package information or embedded credentials, assign a score near 1.
                    5. Environment and Configuration Directories: Directories containing .env files, config directories, or any directory that might hold environment variables, API keys, or application configurations, assign a score near 1.
                    6. Database Directories: Directories related to databases (MySQL, PostgreSQL, MongoDB, SQLite) or any directory containing .db, .sqlite, .sql files that may expose sensitive data, assign a score near 1.
                    7. Log Directories: System log directories (/var/log) or application log directories that may contain sensitive operational information, assign a score between 0.7-1 based on log sensitivity.
                    8. Temporary and Cache Directories: Temporary directories (/tmp, /var/tmp) or cache directories that might contain temporarily stored sensitive data, assign a score between 0.3-0.7 based on location and potential content.
                    9. Hidden Directories: Hidden directories (starting with .) that may contain sensitive system or application data, assign a score between 0.5-1 based on directory purpose.
                    10. Other Considerations: Evaluate any other directories that could potentially expose sensitive information or contain credentials.

                     Return only the final sensitivity score (a floating-point number between 0 and 1) as the output, with no additional explanation or text.
                """,
        },
        {"role": "user", "content": f"""File Path: {dir_path}"""},
    ]
    logger.info(f"[LLM] Analyze the Degree of the Dir Path Sensitivity\nDir Path: {dir_path}")
    try:
        answer = connect_with_retry(messages)
    except ConnectionError:
        answer = 0.5
    try:
        answer_flow = float(answer)
    except ValueError:
        logger.warning(f"[LLM] The return value is not a valid floating-point number: {answer}")
        answer_flow = 0.5
    logger.info(f"[LLM] The Degree of the Dir Path Sensitivity is: {answer}")
    answer_flow = max(0.0, min(answer_flow, 1.0))
    return answer_flow


def llm_path_sensitivity_interpret(file_path: str):
    messages = [
        {
            "role": "system",
            "content": """
                You're a security expert specializing in NPM package analysis and file system security. You are provided with one input:
                File Path: A string representing the Linux file system path that is being accessed, checked, or constructed by path-related APIs (such as fs.exists, fs.open, path.join, path.resolve, etc.).
                Your task is to analyze the sensitivity based on the name and pattern of the path, particularly in the context of NPM packages and Node.js applications that use path-only APIs for file system operations or path manipulation. Based on your expert analysis, assign a sensitivity score as a floating-point number in the range [0, 1] according to the following guidelines:
                 Sensitivity Scoring:
                 0: Not sensitive at all.
                 0 to 0.5: Low sensitivity (act as a warning).
                 0.5 to 1: High sensitivity (should be closely scrutinized).
                 1: Absolutely sensitive.
                 
                 Only report higher score if you are confident of the result.
                 Here are the cases for the analysis of the degree of sensitivity:
                1. System and Critical Configuration Files: File paths in system directories (e.g., `/etc`, `/var`, `/root`) or core system configuration files (e.g., `/etc/passwd`, `/etc/shadow`, `/etc/ssh/sshd_config`, `/etc/sudoers`) should be flagged as highly sensitive, assign a score near 1.
                2. User Home and Configuration Files: Paths to user home directories (`~/`, `/home/username`) or user-specific configuration files (e.g., `~/.bashrc`, `~/.zshrc`, `~/.bash_history`, `~/.zsh_history`) that may expose personal configurations and command histories, assign a score near 1.
                3. Authentication and Security Files: Paths in security directories (`.ssh`, `.gnupg`) or files with keywords like "key", "cert", "pem" (e.g., private keys, certificates) that are inherently sensitive, assign a score near 1.
                4. Environment and Configuration Files: Paths to environment files (`.env`, `.env.local`, `.env.production`) or configuration files that may hold credentials, API keys, or sensitive application settings, assign a score near 1.
                5. Database and Data Files: Paths to database files (extensions like `.db`, `.sqlite`, `.sql`, `.dump`) or database directories that may contain sensitive application data, assign a score near 1.
                6. Log and Temporary Files: Paths to log directories (`/var/log`) or temporary directories (`/tmp`, `/var/tmp`) that might contain sensitive operational information or temporary credentials, assign a score between 0.2-0.8 based on location and context.
                7. Binary and Executable Files: Paths to executable files (`.sh`, `.py`, `.bin`) or executable directories (`/usr/bin`, `/usr/local/bin`) that may pose execution risks, assign a score near 1.
                8. Hidden and Dot Files: Paths to hidden files or directories (starting with `.`) that may contain sensitive system or application data, assign a score between 0.2-1 based on file type and location.
                9. Path Traversal Patterns: Paths containing directory traversal patterns (`../`) or absolute paths that attempt to access sensitive locations outside expected directories, assign a score near 1.
                10. Suspicious Path Constructions: Dynamically constructed paths that combine user input with sensitive directory paths, or paths that use unusual encoding or obfuscation techniques, assign a score between 0.6-1 based on suspicion level.
                11. Other Considerations: Evaluate any other file paths that may indicate storage of configuration settings, database connection strings, certificates, or similar sensitive information that can be used by attackers.
                
                 Return only the final sensitivity score (a floating-point number between 0 and 1) as the output, with no additional explanation or text.
            """,
        },
        {"role": "user", "content": f"""File Path: {file_path}"""},
    ]

    logger.info(f"[LLM] Analyse the Degree of the File Path Sensitivity\nFile Path: {file_path}")
    try:
        answer = connect_with_retry(messages)
    except ConnectionError:
        answer = 0.5
    try:
        answer_flow = float(answer)
    except ValueError:
        logger.warning(f"[LLM] The return value is not a valid floating-point number: {answer}")
        answer_flow = 0.5
    logger.info(f"[LLM] The Degree of the File Path Sensitivity is: {answer}")
    answer_flow = max(0.0, min(answer_flow, 1.0))
    return answer_flow


def llm_file_pattern_sensitivity_interpret(file_pattern: str):
    messages = [
        {
            "role": "system",
            "content": """
                You're a security expert specializing in NPM package analysis and file system security. You are provided with one input:
                File Pattern: A string representing a glob pattern used by functions like fs.glob, fs.globSync, or similar pattern-matching APIs to search for files in a Linux file system.
                Your task is to analyze the sensitivity based on the pattern structure and target files, particularly in the context of NPM packages and Node.js applications that use glob patterns for file discovery, batch operations, or reconnaissance. Based on your expert analysis, assign a sensitivity score as a floating-point number in the range [0, 1] according to the following guidelines:
                0: Not sensitive at all.
                0 to 0.5: Low sensitivity (act as a warning).
                0.5 to 1: High sensitivity (should be closely scrutinized).
                1: Absolutely sensitive.
                
                Only report higher score if you are confident of the result.
                Here are the cases for the analysis of the degree of sensitivity:
                1. System and Critical Configuration Patterns: Patterns targeting system directories (`/etc/**`, `/var/**`, `/root/**`) or core system configuration files (`/etc/passwd`, `/etc/shadow`, `/etc/ssh/*`, `/etc/sudoers`) should be flagged as highly sensitive, assign a score near 1.
                2. User Home and Configuration Patterns: Patterns targeting user directories (`~/.**`, `/home/*/**`) or user-specific configuration files (`~/.bashrc`, `~/.zshrc`, `~/.bash_history`, `~/.ssh/*`) that may expose personal configurations and command histories, assign a score near 1.
                3. Authentication and Security Patterns: Patterns targeting security directories (`**/.ssh/*`, `**/.gnupg/*`) or files with security keywords (`**/*key*`, `**/*cert*`, `**/*pem*`) that are inherently sensitive, assign a score near 1.
                4. Environment and Configuration Patterns: Patterns targeting environment files (`**/.env*`, `**/config/**`, `**/settings/**`) or configuration files that may hold credentials, API keys, or sensitive application settings, assign a score near 1.
                5. Database and Data File Patterns: Patterns targeting database files (`**/*.db`, `**/*.sqlite`, `**/*.sql`, `**/*.dump`) or database directories that may contain sensitive application data, assign a score near 1.
                6. Binary and Executable Patterns: Patterns targeting executable files (`**/*.sh`, `**/*.py`, `**/*.bin`, `/usr/bin/**`, `/usr/local/bin/**`) that may pose execution risks, assign a score near 1.
                7. Hidden File and Directory Patterns: Patterns targeting hidden files or directories (`**/.*`, `**/.*/`) that may contain sensitive system or application data, assign a score between 0.3-0.8 based on pattern specificity.
                8. Wildcard and Broad Sweep Patterns: Overly broad patterns (`**/*`, `/*`, `/**/**`) that attempt to access large portions of the file system for reconnaissance purposes, assign a score between 0.6-0.9 based on scope breadth.
                9. Path Traversal and Escape Patterns: Patterns containing directory traversal elements (`../**`, `**/../**`) or attempts to escape expected directories, assign a score near 1.
                10. Credential and Secret Hunting Patterns: Patterns specifically designed to find credentials (`**/*password*`, `**/*secret*`, `**/*token*`, `**/*api*key*`) or sensitive data, assign a score near 1.
                11. Source Code and Development Patterns: Patterns targeting development files (`**/.git/**`, `**/src/**`, `**/*.js`, `**/*.ts`) that may contain proprietary code or development secrets, assign a score between 0.4-0.7 based on pattern scope.
                12. Other Considerations: Evaluate any other file patterns that may indicate systematic access to configuration settings, database connection strings, certificates, or similar sensitive information for reconnaissance or data collection purposes.

                 Return only the final sensitivity score (a floating-point number between 0 and 1) as the output, with no additional explanation or text.
            """,
        },
        {"role": "user", "content": f"""File Path: {file_pattern}"""},
    ]
    logger.info(f"[LLM] Analyse the Degree of the File Pattern Sensitivity\nFile Pattern: {file_pattern}")
    try:
        answer = connect_with_retry(messages)
    except ConnectionError:
        answer = 0.5
    try:
        answer_flow = float(answer)
    except ValueError:
        logger.warning(f"[LLM] The return value is not a valid floating-point number: {answer}")
        answer_flow = 0.5
    logger.info(f"[LLM] The Degree of the File Pattern Sensitivity is: {answer}")
    answer_flow = max(0.0, min(answer_flow, 1.0))
    return answer_flow


def llm_rm_files_sensitivity_interpret(rm_files: str):
    messages = [
        {
            "role": "system",
            "content": """
                    You're a security expert specializing in NPM package analysis and file system security. You are provided with one input:
                    File Path: A string representing the Linux file system path of the file(s) that are being deleted by file deletion APIs (such as fs.rm, fs.unlink, fs.rmSync, etc.).
                    Your task is to analyze the sensitivity based on the path of the file and the potential impact of its deletion, particularly in the context of NPM packages and Node.js applications. Based on your expert analysis, assign a sensitivity score as a floating-point number in the range [0, 1] according to the following guidelines:
                    0: Not sensitive at all.
                    0 to 0.5: Low sensitivity (act as a warning).
                    0.5 to 1: High sensitivity (should be closely scrutinized).
                    1: Absolutely sensitive.
                    
                    Only report higher score if you are confident of the result.
                    Here are the cases for the analysis of the degree of sensitivity:
                   1. Critical System Files: Deletion of core system files in directories like `/etc`, `/var`, `/bin`, `/usr/bin`, `/root`, or system-critical configuration files (e.g., `/etc/passwd`, `/etc/shadow`, `/etc/ssh/sshd_config`, `/etc/sudoers`, `/etc/crontab`) is highly sensitive as it may cause system instability or complete failure, assign a score near 1.
                   2. User Home and Configuration Files: Deleting user home directories (`~/`, `/home/username`) or user configuration files (e.g., `~/.bashrc`, `~/.zshrc`, `~/.bash_history`, `~/.profile`) that contain personal settings and command histories, assign a score near 1.
                   3. Authentication and Security Files: Deletion of security-related files in directories like `.ssh`, `.gnupg`, or files containing "key", "cert", "pem" in their names (e.g., private keys, certificates) that could compromise system security, assign a score near 1.
                   4. Environment and Configuration Files: Deleting environment files (`.env`, `.env.local`, `.env.production`) or application configuration files that may contain credentials, API keys, or critical application settings, assign a score near 1.
                   5. Database and Data Files: Deletion of database files (extensions like `.db`, `.sqlite`, `.sql`, `.dump`) or database directories that may result in permanent data loss or application failure, assign a score near 1.
                   6. Backup and Recovery Files: Deletion of backup files, archive directories, or recovery data that could prevent system recovery or data restoration in case of failures, assign a score near 1.
                   7. Application and Service Files: Deleting critical application files, service configurations, or executable files that could disrupt application functionality or system services, assign a score between 0.7-1 based on criticality.
                   8. Development and Source Code Files: Deletion of source code files, version control data (`.git` directories), or development configurations that could result in intellectual property loss or development disruption, assign a score between 0.5-0.8 based on file importance.
                   9. Temporary and Cache Files: Deleting temporary files (`/tmp/*`, `/var/tmp/*`), cache files, or non-critical data that can be regenerated or has minimal impact on system operation, assign a score between 0.1-0.3.
                   10. Anti-Forensics and Evidence Destruction: Deletion patterns that appear designed to hide tracks, remove evidence, or interfere with forensic analysis (e.g., systematic deletion of logs, history files, or temporary files), assign a score near 1.
                   11. Mass Deletion and Destructive Patterns: Deletion operations targeting large numbers of files, entire directory trees, or using wildcard patterns that could cause widespread data loss, assign a score between 0.8-1 based on scope and potential impact.
                   12. Other Critical Considerations: Evaluate any other file deletions that could lead to severe system instability, significant data loss, security compromise, or interference with system operations or forensic analysis.
                   
                   Return only the final sensitivity score (a floating-point number between 0 and 1) as the output, with no additional explanation or text.
                """,
        },
        {"role": "user", "content": f"""File Path: {rm_files}"""},
    ]

    logger.info(f"[LLM] Analyse the Degree of the File Deletion Sensitivity\nRemoved Files: {rm_files}")
    try:
        answer = connect_with_retry(messages)
    except ConnectionError:
        answer = 0.5
    try:
        answer_flow = float(answer)
    except ValueError:
        logger.warning(f"[LLM] The return value is not a valid floating-point number: {answer}")
        answer_flow = 0.5
    logger.info(f"[LLM] The Degree of the File Deletion Sensitivity is: {answer}")
    answer_flow = max(0.0, min(answer_flow, 1.0))
    return answer_flow


def llm_execute_file_interpret(file_name: str):
    messages = [
        {
            "role": "system",
            "content": """
                You're a security expert specializing in NPM package analysis and process execution security. You are provided with one input:
                File Name Parameter: A string representing the executable file to be run by process execution APIs (such as child_process.execFile).
                Your task is to evaluate the degree of sensitivity (i.e., the potential maliciousness or suspicious nature) of executing this file based on its name, extension, and execution context, particularly in the context of NPM packages and Node.js applications. Based on your expert analysis, assign a sensitivity score as a floating-point number in the range [0, 1] according to the following guidelines:
                0: Not sensitive at all.
                0 to 0.5: Low sensitivity (act as a warning).
                0.5 to 1: High sensitivity (should be closely scrutinized).
                1: Absolutely sensitive.
                
                Only report higher score if you are confident of the result.
                Guidelines for Analysis:
                1. High-Risk Executables and System Commands: If the file name is a system command or binary (e.g., `sh`, `bash`, `zsh`, `sudo`, `su`, `chmod`, `wget`, `curl`, `nc`) or ends with high-risk extensions such as `.sh`, `.bash`, `.zsh`, assign a score near 1 due to potential for arbitrary command execution and system access.
                2. Non-Standard File Extensions: If the file name ends with an extension that is not commonly associated with executable files (e.g., files with extensions like `.md`, `.txt`, `.json`, `.xml`) or has suspicious obfuscated names, assign a score near 1 as this suggests potential abuse or evasion techniques.
                3. Interpreted Language Scripts: If the file name ends with script file extensions (e.g., `.py` for Python, `.pl` for Perl, `.rb` for Ruby) that can execute arbitrary code, assign a score between 0.5-0.8 based on language capabilities and execution context.
                4. JavaScript and Node.js Files: If the file name ends with `.js`, `.mjs`, `.cjs` and there are no additional suspicious indicators, assign a low score as these are common in Node.js environments.
                5. Network and System Tools: If the file name corresponds to network tools, download utilities, system administration commands, or data processing tools (`wget`, `curl`, `ssh`, `scp`, `tar`, `zip`, `grep`, `find`, `crontab`, `systemctl`) that could be used for data exfiltration, privilege escalation, or reconnaissance, assign a score near 1.
                6. Suspicious File Names and Locations: If the file name contains suspicious keywords (e.g., "malware", "payload", "virus", "backdoor", "trojan") or is located in unusual paths (`/tmp/`, `/var/tmp/`, hidden directories), or is a hidden file (starting with `.`), assign a score near 1.
                7. Other or Unknown Extensions: For file names with uncommon or unknown extensions, package managers (`npm`, `yarn`, `pip`), or any other executables that might pose security risks based on their potential capabilities or execution context, use your expert judgment to assign a sensitivity score between 0.4-1 based on the likelihood of malicious use.
                
                Return only the final sensitivity score (a floating-point number between 0 and 1) as the output, with no additional explanation or text.
            """,
        },
        {"role": "user", "content": f"""File Name: {file_name}"""},
    ]

    logger.info(f"[LLM] Analyse the Degree of the File Execution Sensitivity\nFile Name: {file_name}")
    try:
        answer = connect_with_retry(messages)
    except ConnectionError:
        answer = 0.5
    try:
        answer_flow = float(answer)
    except ValueError:
        logger.warning(f"[LLM] The return value is not a valid floating-point number: {answer}")
        answer_flow = 0.5
    logger.info(f"[LLM] The Degree of the File Execution Sensitivity is: {answer}")
    answer_flow = max(0.0, min(answer_flow, 1.0))
    return answer_flow


def max_token(input_string):
    tokens = enc.encode(str(input_string))
    if len(tokens) > 127000:
        return True
    else:
        return False


def connect_with_retry(prompt, max_attempts=5, delay=1, model=model_name):
    LLM_client = OpenAI(api_key=api_key)

    attempts = 0
    while attempts < max_attempts:
        try:
            completion = LLM_client.chat.completions.create(
                model=model,
                messages=prompt,
                temperature=0,
            )
            answer = completion.choices[0].message.content
            # Attempt to establish the connection here
            if attempts > max_attempts - 1:
                raise ConnectionError("Connection failed")
            else:
                return answer

        except Exception:
            attempts += 1
            if attempts < max_attempts:
                logger.warning(f"Retrying in {delay} seconds...")
                time.sleep(delay)

    # If max attempts are reached without successful connection, raise an exception
    raise ConnectionError("Failed to establish connection to OpenAI after maximum attempts")

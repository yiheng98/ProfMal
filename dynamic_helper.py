import os
import shutil
import traceback

from loguru import logger
import json
from npm_pipeline.classes.code_Info import CodeInfo
import joern_helper
from npm_pipeline.classes.call_graph_info import CallGraph
from npm_pipeline.classes.api_call import APICallCollection
from custom_exception import DynamicRunningException
from custom_exception import DynamicCallGraphEmptyException
from custom_exception import JoernGenerationExceptionInDynamic
from custom_exception import GraphReadingException
import csv
import sys
from ast_parser import ASTParser
import re
import pickle
import docker
from contextlib import contextmanager
import threading
import subprocess
import yaml

csv.field_size_limit(sys.maxsize)

with open("./config.yaml", "r") as file:
    config = yaml.safe_load(file)


@contextmanager
def docker_container_context(image_tar_path: str, volume_mapping: dict):
    """Load Image and create container, and remove after finishing"""
    container_cmd = "bash"
    image_tag: str = "dynamic_env:latest"
    client = docker.from_env()
    try:
        image = client.images.get(image_tag)
        logger.info(f"Using cached image with tag: {image_tag}")
    except Exception as e:
        logger.info(f"Loading image from tar file: {image_tar_path} of {e}")
        with open(image_tar_path, "rb") as f:
            images = client.images.load(f.read())
        image = images[0]

    def create_container():
        return client.containers.run(
            image=image.id, detach=True, tty=True, command=container_cmd, volumes=volume_mapping, network_mode="host"
        )

    # create container
    container = create_container()
    try:
        yield container
    finally:
        try:
            container.stop()
        except Exception as e:
            logger.error(f"Error stopping container: {e}")
        try:
            container.remove()
        except Exception as e:
            logger.error(f"Error removing container: {e}")


def stop_container(container):
    try:
        logger.info("Stopping and removing container due to timeout.")
        container.stop()
    except Exception as e:
        logger.error(f"Error stopping and removing container: {e}")


def docker_execute_command(container, cmd, args, workdir, env, label, timeout=90):
    """
    run command in the docker container
    """
    full_cmd = [cmd] + args
    logger.info(f"[Docker] {label} execution: {' '.join(full_cmd)} (workdir: {workdir})")

    # Set timer to stop container after timeout
    timeout_timer = threading.Timer(timeout, stop_container, [container])
    timeout_timer.start()  # Start timer

    try:
        result = container.exec_run(
            cmd=full_cmd,
            workdir=workdir,
            environment=env,
            stdout=True,
            stderr=True,
            demux=True,
        )
    except Exception as e:
        logger.error(f"{label} command execution failed with error: {str(e)}")
        raise Exception(f"{label} command execution failed with error: {str(e)}")
    finally:
        timeout_timer.cancel()

    stdout, stderr = result.output if result.output else (b"", b"")
    if stdout:
        logger.info(f"{label}: {stdout.decode('utf-8')}")
    if stderr:
        logger.info(f"{label}: {stderr.decode('utf-8')}")
    if result.exit_code != 0:
        logger.error(Exception(f"{label} command failed with exit code {result.exit_code}"))
    else:
        logger.info(f"Docker {label} execution finished successfully.")


def generate_dynamic_info(
    package_dir: str,
    formatted_package_dir: str,
    joern_dir: str,
    pdg_dir: str,
    cfg_dir: str,
    cpg_dir: str,
    jelly_cg_dir: str,
    api_info_dir: str,
    overwrite: bool,
    entry_file: str,
    pickle_file_path: str,
    static_code_info: CodeInfo,
    file_in_cg: set,
):
    if not overwrite and os.path.exists(pickle_file_path):
        try:
            with open(pickle_file_path, "rb") as f:
                dynamic_code_info = pickle.load(f)
            return dynamic_code_info
        except Exception as e:
            logger.error(f"Failed to load pickle file: {e}")

    move_folder(package_dir, formatted_package_dir)

    # preprocess the code
    code_preprocess(formatted_package_dir)

    # dynamic execution to generate the call graph and `eval` info
    dynamic_call_graph, api_call_info, has_eval = dynamic_info_export(
        formatted_package_dir, jelly_cg_dir, api_info_dir, entry_file, file_in_cg
    )

    if dynamic_call_graph is None:
        if static_code_info:
            dynamic_code_info = static_code_info
            dynamic_code_info.set_api_call_info(api_call_info)
            logger.warning("Dynamic Call Graph is None, using the static one")
            try:
                with open(pickle_file_path, "wb") as f:
                    pickle.dump(dynamic_code_info, f)
                logger.info("Saved dynamic_code_info to binary file.")
            except Exception as e:
                logger.error(f"Failed to save dynamic_code_info: {e}")
            return dynamic_code_info
        else:
            raise DynamicCallGraphEmptyException("Dynamic Call Graph Failed", api_call_info)

    joern_re_generate = True
    dynamic_code_info = None
    # merge the call graph from the dynamic to the static
    if static_code_info and not has_eval:
        addition_files = merge_call_graph(static_code_info.call_graph, dynamic_call_graph)
        if not addition_files:
            # keep the Joern result
            joern_re_generate = False
            dynamic_code_info = static_code_info
            dynamic_code_info.set_call_graph(dynamic_call_graph)
            dynamic_code_info.set_api_call_info(api_call_info)
            logger.info("Use the Joern Result in Static Analysis")
    if joern_re_generate:
        remove_file_not_in_cg(dynamic_call_graph, formatted_package_dir)
        joern_helper.joern_export(formatted_package_dir, joern_dir, "javascript", overwrite=True)
        try:
            pdg_graph_dict, cpg = joern_helper.joern_preprocess(formatted_package_dir, pdg_dir, cfg_dir, cpg_dir)
        except GraphReadingException as e:
            logger.warning(f"Joern preprocess error of {e}")
            raise JoernGenerationExceptionInDynamic("Joern export failed in Dynamic Execution", api_call_info)

        # the error in dynamic analysis is less critical than static analysis
        if not len(os.listdir(pdg_dir)) > 0:
            logger.warning("PDG not found in dynamic execution")
            raise JoernGenerationExceptionInDynamic("Joern export failed in Dynamic Execution", api_call_info)
        if not len(os.listdir(cfg_dir)):
            logger.warning("CFG not found in dynamic execution")
            raise JoernGenerationExceptionInDynamic("Joern export failed in Dynamic Execution", api_call_info)
        if not len(os.listdir(cpg_dir)):
            logger.warning("CPG not found in dynamic execution")
            raise JoernGenerationExceptionInDynamic("Joern export failed in Dynamic Execution", api_call_info)

        dynamic_code_info = CodeInfo(formatted_package_dir, pdg_dir, cpg_dir, pdg_graph_dict, cpg)
        dynamic_code_info.set_call_graph(dynamic_call_graph)
        dynamic_code_info.set_api_call_info(api_call_info)
    try:
        with open(pickle_file_path, "wb") as f:
            pickle.dump(dynamic_code_info, f)
        logger.info("Saved dynamic_code_info to binary file.")
    except Exception as e:
        logger.error(f"Failed to save dynamic_code_info: {e}")
    return dynamic_code_info


def dynamic_info_export(
    package_code_dir: str, dynamic_call_graph_dir: str, api_locate_dir: str, entry_file: str, file_in_cg: set
):
    """
    export the dynamic info, including call graph and API call location
    """

    if os.path.exists(dynamic_call_graph_dir):
        shutil.rmtree(dynamic_call_graph_dir)
    if os.path.exists(api_locate_dir):
        shutil.rmtree(api_locate_dir)

    os.makedirs(dynamic_call_graph_dir, exist_ok=True)
    os.makedirs(api_locate_dir, exist_ok=True)

    # create a empty csv file
    api_info_csv_file_path = os.path.join(api_locate_dir, "api_info.csv")
    with open(api_info_csv_file_path, mode="w", newline="") as file:
        csv.writer(file)

    source_code_path = os.path.join(package_code_dir, "package")
    custom_dyn_file_path = os.path.abspath(os.path.join(os.getcwd(), "dyn.js"))
    custom_node_file_path = os.path.abspath(os.path.join(os.getcwd(), "node"))

    # path mapping
    CONTAINER_APP_PATH = "/app"
    CONTAINER_JELLY_OUT = "/jelly_out"
    CONTAINER_API_INFO = "/api_info"
    CONTAINER_DYN_PATH = "/lib/node_modules/@cs-au-dk/jelly/lib/dynamic/dyn.js"
    CONTAINER_CUSTOM_NODE_PATH = "/lib/node_modules/@cs-au-dk/jelly/bin/node"

    volume_mapping = {
        os.path.abspath(source_code_path): {"bind": CONTAINER_APP_PATH, "mode": "rw"},
        os.path.abspath(dynamic_call_graph_dir): {"bind": CONTAINER_JELLY_OUT, "mode": "rw"},
        os.path.abspath(api_locate_dir): {"bind": CONTAINER_API_INFO, "mode": "rw"},
        os.path.abspath(custom_dyn_file_path): {"bind": CONTAINER_DYN_PATH, "mode": "ro"},
        os.path.abspath(custom_node_file_path): {"bind": CONTAINER_CUSTOM_NODE_PATH, "mode": "ro"},
    }

    image_tar_path = os.path.abspath(os.path.join(os.getcwd(), "..", "dynamic_env.tar"))

    # execute command in the same container
    with docker_container_context(image_tar_path=image_tar_path, volume_mapping=volume_mapping) as container:
        # remove the scripts in the package.json
        remove_scripts_in_package_json(source_code_path)

        # STEP 1 install the package
        docker_execute_command(
            container,
            "npm",
            ["install", "--omit=dev", "--registry", "https://registry.npmmirror.com//"],
            workdir=CONTAINER_APP_PATH,
            env={},
            label="npm install",
            timeout=300,
        )

        # Generate dynamic call graph while parsing for eval existence
        custom_node_cmd = "jelly"
        graal_home = "/workspace-nodeprof/graal/sdk/latest_graalvm_home"  # Path in container image
        env_vars = {"GRAAL_HOME": graal_home, "CALL_FILE": CONTAINER_JELLY_OUT}

        # STEP 2 Dynamic Call Graph Generation
        try:
            docker_execute_command(
                container,
                custom_node_cmd,
                [entry_file, "-d", os.path.join(CONTAINER_JELLY_OUT, "cg.json"), "--basedir", CONTAINER_APP_PATH],
                workdir=CONTAINER_APP_PATH,
                env=env_vars,
                label="dynamic info",
            )

            cg_path = os.path.join(dynamic_call_graph_dir, "cg.json")
            if not os.path.exists(cg_path):
                dynamic_call_graph = None
            else:
                cg_json_data = json.load(open(cg_path, "r"))
                dynamic_call_graph = build_dynamic_call_graph(cg_json_data)
                file_in_cg.update(dynamic_call_graph.get_files())
                # Dynamic jelly lacks the `require` call to the source file
                add_call_to_source_file(dynamic_call_graph_dir, dynamic_call_graph)

            # Check for `eval` function
            check_eval = check_and_replace_eval(dynamic_call_graph_dir, package_code_dir)
            if check_eval:
                # If eval exists, remove the jelly output
                for filename in os.listdir(dynamic_call_graph_dir):
                    file_path = os.path.join(dynamic_call_graph_dir, filename)
                    if os.path.isfile(file_path):
                        os.remove(file_path)

                # Empty the api_info.csv
                with open(api_info_csv_file_path, mode="w", newline="") as file:
                    csv.writer(file)

                # Re-run
                docker_execute_command(
                    container,
                    custom_node_cmd,
                    [entry_file, "-d", os.path.join(CONTAINER_JELLY_OUT, "cg.json")],
                    workdir=CONTAINER_APP_PATH,
                    env=env_vars,
                    label="dynamic info",
                )

                cg_path = os.path.join(dynamic_call_graph_dir, "cg.json")
                if not os.path.exists(cg_path):
                    dynamic_call_graph = None
                else:
                    with open(cg_path, "r", encoding="utf-8") as f:
                        cg_json_data = json.load(f)
                    dynamic_call_graph = build_dynamic_call_graph(cg_json_data)
                    file_in_cg.update(dynamic_call_graph.get_files())
                    add_call_to_source_file(dynamic_call_graph_dir, dynamic_call_graph)
        except Exception as e:
            logger.error(f"Dynamic Info Execution Failed of {e}")
            dynamic_call_graph = None
            check_eval = False

    # STEP 3 Get the API Info
    preprocess_api_call_info(api_info_csv_file_path, package_code_dir, CONTAINER_APP_PATH)
    api_call_info_json_path = os.path.join(api_locate_dir, "api_info.json")
    if not os.path.exists(api_call_info_json_path):
        raise DynamicRunningException("Dynamic Call Graph Generation Error: api_info.json not found")
    apI_call_info = APICallCollection(api_call_info_json_path)
    return dynamic_call_graph, apI_call_info, check_eval


def remove_scripts_in_package_json(source_code_path: str):
    package_json_path = os.path.join(source_code_path, "package.json")
    if not os.path.exists(package_json_path):
        return
    else:
        with open(package_json_path, "r") as file:
            package_data = json.load(file)

        if "scripts" in package_data:
            del package_data["scripts"]
            with open(package_json_path, "w") as file:
                json.dump(package_data, file, indent=4)


def check_and_replace_eval(eval_trace_dir: str, package_code_dir: str):
    call_pattern = re.compile(r"^\(([^:]+):\d+:\d+:\d+:\d+\)$")
    valid_entries = []
    for entry in os.scandir(eval_trace_dir):
        # Only process files whose names start with "eval_trace-"
        if entry.is_file() and entry.name.startswith("eval_trace-"):
            file_path = os.path.abspath(os.path.join(eval_trace_dir, entry.name))
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    # Ensure data is a list
                    if isinstance(data, list):
                        for item in data:
                            # Ensure data item is a dictionary with "Call" field as string
                            if isinstance(item, dict) and "Call" in item and isinstance(item["Call"], str):
                                # Keep if Call matches expected format
                                match = call_pattern.match(item["Call"])
                                if match:
                                    valid_entries.append(item)
            except Exception as e:
                logger.error(f"Error reading JSON from {file_path}: {e}")

    if len(valid_entries) == 0:
        return False

    replacements_by_file = {}
    for item in valid_entries:
        call_loc = item.get("Call")
        arg = item.get("Arg")
        loc_str = call_loc.strip("()")
        split_res = loc_str.split(":")
        file_name = split_res[0]
        start_line = int(split_res[1])
        start_column = int(split_res[2])
        end_line = int(split_res[3])
        end_column = int(split_res[4])
        file_host_path = os.path.join(package_code_dir, "package", file_name)
        replacements_by_file.setdefault(file_host_path, []).append(
            {
                "start_line": start_line,
                "start_column": start_column,
                "end_line": end_line,
                "end_column": end_column,
                "arg": arg,
                "call_loc": call_loc,
            }
        )

    replaced = False

    for file_path, replacements in replacements_by_file.items():
        if not os.path.exists(file_path):
            continue

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            logger.error(f"Failed to read {file_path}: {e}")
            continue

        # Use splitlines to preserve line breaks
        lines = content.splitlines(keepends=True)

        parser = ASTParser(content)
        eval_wraps = []
        wrap_counter = 1

        def get_offset(line_no, col_no):
            """
            Calculate absolute character offset based on line and column numbers.
            """
            # Sum lengths of all preceding lines, then add column offset within current line
            offset = sum(len(lines[i]) for i in range(line_no - 1)) + (col_no - 1)
            return offset

        # Build replacement list, converting to absolute offsets
        replacement_entries = []
        for rep in replacements:
            if rep["start_line"] > len(lines) or rep["end_line"] > len(lines):
                logger.error(f"Line number out of range, file {file_path}, replacement: {rep}")
                continue

            target_node = parser.find_call_expression_by_start_end_point(
                rep["start_line"], rep["start_column"], rep["end_line"], rep["end_column"]
            )
            if target_node is None:
                logger.info(f"Cannot find target node, file {file_path}, replacement: {rep}")
                continue

            if not parser.is_isolated_eval(target_node):
                continue

            start_offset = get_offset(rep["start_line"], rep["start_column"])
            end_offset = get_offset(rep["end_line"], rep["end_column"])
            wrap_func_name = f"eval_wrap_{wrap_counter}"
            wrap_counter += 1
            replacement_entries.append(
                {"start_offset": start_offset, "end_offset": end_offset, "replacement": f"{wrap_func_name}()"}
            )
            eval_wraps.append(f"""function {wrap_func_name}() {{
              {rep["arg"]}
            }}""")

        # Sort by start_offset in descending order to ensure later replacements are performed first
        replacement_entries.sort(key=lambda x: x["start_offset"], reverse=True)

        result_code = content
        for rep in replacement_entries:
            logger.info(
                f"Replacing content in file {file_path} at interval [{rep['start_offset']}, {rep['end_offset']}) with: {rep['replacement']}"
            )
            result_code = result_code[: rep["start_offset"]] + rep["replacement"] + result_code[rep["end_offset"] :]
            replaced = True
        if eval_wraps:
            result_code += "\n\n" + "\n\n".join(eval_wraps) + "\n"

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(result_code)
        except Exception as e:
            logger.error(f"Write File: {file_path} Error: {e}")

    if replaced:
        return True
    else:
        return False


def safe_json_load(value, default=None):
    try:
        return json.loads(value) if value else default
    except json.JSONDecodeError:
        return default


def preprocess_api_call_info(api_info_file_path: str, package_code_dir: str, container_app_path: str):
    chmod_command = ["sudo", "-S", "chmod", "-R", "777", package_code_dir]
    try:
        subprocess.run(chmod_command, input=f"{config['sudo_passwd']}\n", text=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to change permissions: {e}")

    def get_string(csv_item):
        if csv_item.startswith('"') and csv_item.endswith('"'):
            csv_item = csv_item[1:-1]
        return csv_item.replace('""', '"')

    columns = ["func_type", "module_name", "func_name", "argument", "results", "file", "line", "column"]
    csv_data = []

    # Read data from CSV
    with open(api_info_file_path, mode="r", encoding="utf-8") as f:
        csvreader = csv.reader(f)
        for row in csvreader:
            try:
                if len(row) != len(columns):  # Skip rows that don't match the expected number of columns
                    continue

                row_dict = dict(zip(columns, row))

                # Process fields that may have been sanitized (argument, results)
                row_dict["argument"] = get_string(row_dict["argument"])
                row_dict["results"] = get_string(row_dict["results"])

                entry = {
                    "type": row_dict["func_type"],
                    "module": row_dict["module_name"],
                    "function": row_dict["func_name"],
                    "arguments": row_dict["argument"],
                    "result": row_dict["results"],
                    "file": row_dict["file"],
                    "line": safe_json_load(row_dict["line"]),
                    "column": safe_json_load(row_dict["column"]),
                }
                csv_data.append(entry)

            except Exception as row_error:
                logger.warning(f"Error processing row {row}: {row_error}")

    # Separate callback entries
    call_back = [entry for entry in csv_data if entry.get("type") == "callback"]
    non_callback = [entry for entry in csv_data if entry.get("type") != "callback"]

    # Cache file contents for faster AST parsing
    code_cache = {}

    # Process the non callback data
    for entry in non_callback:
        _type = entry.get("type")
        file = entry.get("file")
        line = entry.get("line")
        column = entry.get("column")

        if _type and file and line and column:
            relative_inside = os.path.relpath(file, container_app_path)
            file_host_path = os.path.join(package_code_dir, "package", relative_inside)
            relative_file_path = os.path.relpath(file_host_path, package_code_dir)
            caller = {"file": relative_file_path}

            try:
                if file_host_path not in code_cache:
                    with open(file_host_path, "r", encoding="utf-8") as code_file:
                        code_cache[file_host_path] = code_file.read()

                raw_code = code_cache[file_host_path]
                ast_parser = ASTParser(raw_code)

                if _type == "function":
                    call_loc = ast_parser.get_call_expression_loc(line - 1, column - 1)
                    if call_loc:
                        caller.update(
                            {
                                "start_line": call_loc[0],
                                "start_column": call_loc[1],
                                "end_line": call_loc[2],
                                "end_column": call_loc[3],
                            }
                        )
                elif _type == "property":
                    property_access_loc = ast_parser.get_property_access_loc(line - 1, column - 1)
                    if property_access_loc:
                        caller.update(
                            {
                                "start_line": property_access_loc[0],
                                "start_column": property_access_loc[1],
                                "end_line": property_access_loc[2],
                                "end_column": property_access_loc[3],
                            }
                        )
                entry["caller"] = caller
            except Exception as e:
                logger.warning(f"Failed to get call expression loc for {file}: {e}")
                caller.update({"start_line": line, "start_column": column, "end_line": None, "end_column": None})
                entry["caller"] = caller

    # Process callback entries (readFile, readFileSync)
    for entry in call_back:
        arguments = entry.get("arguments", [])
        result = entry.get("result", "")

        if arguments and isinstance(arguments, str):
            for non_callback_entry in reversed(non_callback):
                non_callback_arguments = non_callback_entry.get("arguments", [])
                if (
                    non_callback_arguments
                    and isinstance(non_callback_arguments, str)
                    and non_callback_arguments == arguments
                ):
                    non_callback_entry["result"] = result
                    break

    # Write the filtered and processed data back to a JSON file
    json_file_path = api_info_file_path.replace(".csv", ".json")
    with open(json_file_path, "w", encoding="utf-8") as f:
        json.dump(non_callback, f, indent=2, ensure_ascii=False)
    logger.info("Processed data saved")


def remove_file_not_in_cg(call_graph: CallGraph, format_dir: str):
    files = call_graph.get_files()
    if len(files) == 0:
        return
    package_dir = format_dir
    files_to_keep = set(os.path.normpath(file_path) for file_path in files)

    for root, dirs, files in os.walk(package_dir, topdown=False):
        for file in files:
            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(file_path, package_dir)
            rel_path_normalized = os.path.normpath(rel_path)
            if rel_path_normalized not in files_to_keep:
                try:
                    os.remove(file_path)
                except Exception as e:
                    logger.warning(f"Failed to remove file: {file_path} of {e}")
        for _dir in dirs:
            dir_path = os.path.join(root, _dir)
            try:
                if not os.listdir(dir_path):
                    os.rmdir(dir_path)
            except Exception as e:
                logger.info(f"Error deleting directory '{dir_path}': {e}")


def build_dynamic_call_graph(call_graph_json):
    dynamic_call_graph = CallGraph()
    entries = call_graph_json["entries"]
    if len(entries) != 0:
        for entry in entries:
            dynamic_call_graph.add_entries(entry)

    files = call_graph_json["files"]
    if len(files) != 0:
        for file in files:
            dynamic_call_graph.add_file(file)

    functions = call_graph_json["functions"]
    if len(functions) != 0:
        for key, value in enumerate(functions):
            split_value = value.split(":")
            dynamic_call_graph.add_function(
                key,
                int(split_value[0]),
                int(split_value[1]) - 1,
                int(split_value[2]) - 1,
                int(split_value[3]) - 1,
                int(split_value[4]) - 1,
            )

    calls = call_graph_json["calls"]
    if len(calls) != 0:
        for key, value in enumerate(calls):
            split_value = value.split(":")
            dynamic_call_graph.add_call(
                key,
                int(split_value[0]),
                int(split_value[1]) - 1,
                int(split_value[2]) - 1,
                int(split_value[3]) - 1,
                int(split_value[4]) - 1,
            )

    call2func_list = call_graph_json["call2fun"]
    if len(call2func_list) != 0:
        for call2func in call2func_list:
            call_id = call2func[0]
            func_id = call2func[1]
            dynamic_call_graph.add_call_to_function(call_id, func_id)

    return dynamic_call_graph


def add_call_to_source_file(dynamic_call_graph_dir: str, dynamic_call_graph: CallGraph):
    for entry in os.scandir(dynamic_call_graph_dir):
        if entry.is_file():
            p = os.path.abspath(os.path.join(dynamic_call_graph_dir, entry.name))
            # Check if the file name starts with "cg-"
            if entry.name.startswith("call_file_source-"):
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        pairs = extract_call2source(data)
                        for pair in pairs:
                            call_info = pair["call"]
                            caller_split_res = call_info.split(":")
                            if not caller_split_res[1].startswith("/usr/lib"):
                                caller = (
                                    caller_split_res[1],
                                    int(caller_split_res[2]) - 1,
                                    int(caller_split_res[3]) - 1,
                                    int(caller_split_res[4]) - 1,
                                    int(caller_split_res[5]) - 1,
                                )

                                callee_info = pair["source"]
                                callee_split_res = callee_info.split(":")

                                if not callee_split_res[1].startswith("/usr/lib"):
                                    callee = (
                                        callee_split_res[1],
                                        int(callee_split_res[2]) - 1,
                                        int(callee_split_res[3]) - 1,
                                        int(callee_split_res[4]) - 1,
                                        int(callee_split_res[5]) - 1,
                                    )
                                    dynamic_call_graph.add_call_to_function_dynamic(caller, callee)
                except Exception as e:
                    logger.error(f"Error decoding JSON from {p}: {e}")
                    logger.error(traceback.format_exc())


def extract_call2source(json_data):
    pairs = []

    for i, item in enumerate(json_data):
        if item.startswith("Source:"):
            # Look backwards for the first "Call:" item
            for j in range(i - 1, -1, -1):
                if json_data[j].startswith("Call:"):
                    new_str = json_data[j].replace("(", "").replace(")", "")
                    pairs.append({"call": new_str, "source": item})
                    break

    return pairs


def move_folder(source, destination):
    """
    Move the source code to the destination
    """
    if os.path.exists(destination):
        shutil.rmtree(destination)
    shutil.copytree(source, destination)


def merge_call_graph(static_graph: CallGraph, dynamic_graph: CallGraph):
    additional_file = False
    files_in_dynamic = dynamic_graph.get_files()
    files_in_static = static_graph.get_files()
    files_not_in_static = [file for file in files_in_dynamic if file not in files_in_static]
    if files_not_in_static:
        additional_file = True

    for file in static_graph.get_files():
        if file not in dynamic_graph.files:
            dynamic_graph.add_file_from_other_call_graph(file)

    # Merge call-to-function mappings from static graph into dynamic graph
    for call_id, call in static_graph.calls.items():
        loc_str = f"{call.start_line}:{call.start_column}:{call.end_line}:{call.end_column}"

        # If the call location (loc_str) is already in the dynamic graph, skip it
        if call.file in dynamic_graph.call2funcs and loc_str in dynamic_graph.call2funcs[call.file]:
            continue

        # Check if there is a function mapping for this call in the static graph
        if call.call_to_function:
            dynamic_graph.add_call_to_function_in_dynamic(call, call.call_to_function)

    return additional_file


def code_preprocess(pkg_dir):
    js_files = []
    for root, dirs, files in os.walk(pkg_dir):
        for file in files:
            if file.endswith((".js", ".cjs", ".mjs")):
                file_path = os.path.join(root, file)
                # Only add file if its path does NOT contain 'node_modules'
                if "node_modules" not in file_path:
                    js_files.append(file_path)
    for file in js_files:
        format_code(file)


def format_code(path):
    # Format the code
    with open(path, "r") as code_file:
        try:
            code = code_file.read()
            # formatted_code = jsbeautifier.beautify(code)
            unescaped_code = unicode_unescape(code)
            with open(path, "w") as code_write_ile:
                code_write_ile.write(unescaped_code)
        except Exception as e:
            logger.warning(f"Format Code failed: {e}")


def unicode_unescape(code):
    """
    Unescape the unicode characters
    """
    unicode_escape_pattern = r"\\u[0-9A-Fa-f]{4}"
    identifier_query = """
        ((identifier) @identifier)
    """
    property_identifier_query = """
        ((property_identifier) @property_identifier)
    """
    private_property_identifier_query = """
        ((private_property_identifier) @private_property_identifier)
    """
    shorthand_property_identifier_query = """
        ((shorthand_property_identifier) @shorthand_property_identifier)
    """
    identifier_family_query = [
        identifier_query,
        property_identifier_query,
        private_property_identifier_query,
        shorthand_property_identifier_query,
    ]
    for query in identifier_family_query:
        offset = 0
        parser = ASTParser(code)
        result = parser.query(query)
        if result:
            for res in result:
                byte_range = res[0].byte_range
                start_index = byte_range[0] + offset
                end_index = byte_range[1] + offset
                identifier = res[0].text.decode()
                # Check whether the identifier is escaped unicode
                if re.search(unicode_escape_pattern, identifier):
                    # Unescape the unicode character
                    try:
                        unescaped_identifier = bytes(identifier, "utf-8").decode("unicode_escape")
                        logger.info(f"Unescape the unicode character: {identifier} -> {unescaped_identifier}")
                    except UnicodeDecodeError:
                        unescaped_identifier = identifier
                    code = code[:start_index] + unescaped_identifier + code[end_index:]
                    offset += len(unescaped_identifier) - (end_index - start_index)

    return code

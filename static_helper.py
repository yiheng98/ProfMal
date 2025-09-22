import os
import json
import pickle
import shutil
import joern_helper
import jelly_helper
from loguru import logger
from ast_parser import ASTParser
import re
from npm_pipeline.classes.code_Info import CodeInfo
import subprocess
from custom_exception import JoernGenerationException
from custom_exception import NoEntryScriptException


def generate_static_info(
    cfg_dir,
    cpg_dir,
    format_dir,
    jelly_cg_path,
    joern_dir,
    pickle_path,
    overwrite,
    package_dir,
    pdg_dir,
    entry_script_set,
):
    if (
        os.path.exists(joern_dir)
        and os.path.exists(pdg_dir)
        and os.path.exists(cfg_dir)
        and os.path.exists(cpg_dir)
        and not overwrite
        and os.path.exists(pickle_path)
    ):
        # If the package has been analysed by Joern and the `overwrite` is False, then skip the preprocessing
        try:
            with open(pickle_path, "rb") as f:
                static_code_info = pickle.load(f)
            return static_code_info
        except Exception as e:
            logger.error(f"Failed to load pickle file: {e}")
    else:
        # move the source code to a new directory, avoid altering the original code
        move_folder(package_dir, format_dir)
        cwd = os.path.join(format_dir, "package")
        install_dependencies(cwd)

        if not entry_script_set:
            raise NoEntryScriptException("There is no entry script")
        # preprocess the code
        code_preprocess(format_dir)

        jelly_helper.jelly_export(format_dir, jelly_cg_path, entry_script_set, overwrite=overwrite)
        remove_file_not_in_cg(jelly_cg_path, format_dir)
        joern_helper.joern_export(format_dir, joern_dir, "javascript", overwrite=overwrite)
        pdg_graph_dict, cpg = joern_helper.joern_preprocess(format_dir, pdg_dir, cfg_dir, cpg_dir)

        if not len(os.listdir(pdg_dir)):
            logger.error("Joern PDG does not exist")
            raise JoernGenerationException("Joern pdg missing")
        if not len(os.listdir(cfg_dir)):
            logger.error("Joern CFG does not exist")
            raise JoernGenerationException("Joern cfg missing")
        if not len(os.listdir(cpg_dir)):
            logger.error("Joern CPG does not exist")
            raise JoernGenerationException("Joern cpg missing")
        static_code_info = CodeInfo(format_dir, pdg_dir, cpg_dir, pdg_graph_dict, cpg)
        static_code_info.build_static_call_graph(jelly_cg_path)
        try:
            with open(pickle_path, "wb") as f:
                pickle.dump(static_code_info, f)
            logger.info("Saved static code info to binary file.")
        except Exception as e:
            logger.error(f"Failed to save static code info: {e}")
        return static_code_info


def install_dependencies(cwd: str, timeout: int = 120):
    logger.info("Installing Dependencies...")
    command = [
        "npm",
        "install",
        "--ignore-scripts",
        "--no-audit",
        "--production",
        "--registry",
        "https://registry.npmmirror.com//",
    ]
    try:
        # Execute the command in the specified working directory
        _ = subprocess.run(
            command,
            cwd=cwd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        logger.info("Dependencies installed successfully.")
    except subprocess.CalledProcessError as error:
        logger.warning("Error occurred while installing dependencies")
        logger.warning(error)
    except subprocess.TimeoutExpired:
        logger.warning("Dependency installation timed out.")
        raise TimeoutError(f"Installation timed out after {timeout} seconds.")


def remove_file_not_in_cg(jelly_cg_path, format_dir):
    with open(jelly_cg_path, "r") as cg_file:
        json_data = json.load(cg_file)

    files = json_data["files"]
    if len(files) == 0:
        return
    package_dir = os.path.join(format_dir, "package")
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


def move_folder(source, destination):
    """
    move the source code to the destination
    """
    if os.path.exists(destination):
        shutil.rmtree(destination)
    shutil.copytree(source, destination)


def code_preprocess(pkg_dir):
    logger.info("Start Code Preprocess")
    js_files = []
    for root, dirs, files in os.walk(pkg_dir):
        # Remove any directories containing "node_modules" so they won't be traversed.
        dirs[:] = [d for d in dirs if "node_modules" not in d]
        for file in files:
            if file.endswith((".js", ".cjs", ".mjs")):
                file_path = os.path.join(root, file)
                js_files.append(file_path)
    for file in js_files:
        format_code(file)
    logger.info("Finish Code Preprocess")


def format_code(path):
    # format the code
    with open(path, "r") as code_file:
        try:
            code = code_file.read()
            unescaped_code = unicode_unescape(code)
            after_eval_code = resolve_eval(unescaped_code)
            with open(path, "w") as code_write_ile:
                code_write_ile.write(after_eval_code)
        except Exception as e:
            logger.warning(f"Format Code failed: {e}")


def resolve_eval(code: str):
    parser = ASTParser(code)
    query = """(
          call_expression
            function: (identifier) @func_name
            arguments: (arguments) @args
          (#eq? @func_name "eval")
        ) @eval_call
    """
    query_result = parser.query(query)
    arg_list = [r[0] for r in query_result if r[1] == "args"]
    eval_call_list = [r[0] for r in query_result if r[1] == "eval_call"]
    replacements = []
    eval_wrap_functions = []
    wrap_counter = 1
    code_lines = code.splitlines(keepends=True)  # Keep line breaks for line-based positioning
    for eval_node, args_node in zip(eval_call_list, arg_list):
        if not parser.is_isolated_eval(eval_node):
            continue
        fragment_nodes = []

        # Recursively find all nodes of type "string_fragment" under args_node
        def collect_fragments(node):
            if node.named_children:
                for child in node.named_children:
                    if not collect_fragments(child):
                        return False
                return True
            else:
                if node.type == "string_fragment":
                    fragment_nodes.append(node)
                    return True
                else:
                    return False

        if collect_fragments(args_node):
            eval_code_text = "".join([fragment.text.decode() for fragment in fragment_nodes])
            logger.info("Find eval function with string, extract the code")
            wrap_func_name = f"eval_wrap_{wrap_counter}"
            wrap_counter += 1
            (start_row, start_col) = eval_node.start_point
            (end_row, end_col) = eval_node.end_point
            replacements.append(((start_row, start_col), (end_row, end_col), f"{wrap_func_name}()"))

            wrapped_fn_code = f"""function {wrap_func_name}() {{
                             {eval_code_text};
            }}"""
            eval_wrap_functions.append(wrapped_fn_code)

    for start_pos, end_pos, replacement in sorted(replacements, key=lambda x: (x[0][0], x[0][1]), reverse=True):
        start_row, start_col = start_pos
        end_row, end_col = end_pos

        # Replace text in the specified row and column range
        before = "".join(code_lines[:start_row]) + code_lines[start_row][:start_col]
        after = code_lines[end_row][end_col:] + "".join(code_lines[end_row + 1 :])
        code_lines = list(before + replacement + after)
        code_lines = "".join(code_lines).splitlines(keepends=True)

    new_code = "".join(code_lines)

    if eval_wrap_functions:
        new_code += "\n\n" + "\n\n".join(eval_wrap_functions) + "\n"

    return new_code


def unicode_unescape(code):
    """
    unescape the unicode characters
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
                # judge whether the identifier is escaped unicode
                if re.search(unicode_escape_pattern, identifier):
                    # unescape the unicode character
                    try:
                        unescaped_identifier = bytes(identifier, "utf-8").decode("unicode_escape")
                        logger.info(f"Unescape the unicode character: {identifier} -> {unescaped_identifier}")
                    except UnicodeDecodeError:
                        unescaped_identifier = identifier
                    code = code[:start_index] + unescaped_identifier + code[end_index:]
                    offset += len(unescaped_identifier) - (end_index - start_index)

    return code

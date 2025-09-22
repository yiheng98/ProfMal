import os
import subprocess
from custom_exception import JellyCallGraphGenerationError
from loguru import logger


def jelly_export(package_code_path: str, call_graph_path: str, entry_script_set: set[str], overwrite: bool = False):
    """
    export the jelly call graph
    :param package_code_path: package code path
    :param call_graph_path: jelly workspace
    :param entry_script_set: the entry script list
    :param overwrite: 是否覆盖已有的 cpg 和 pdg
    """
    if os.path.exists(call_graph_path) and not overwrite:
        return
    else:
        if os.path.exists(call_graph_path):
            os.remove(call_graph_path)
    parent_dir = os.path.dirname(call_graph_path)
    os.makedirs(parent_dir, exist_ok=True)
    source_code_path = os.path.join(package_code_path, "package")
    logger.info("Generate Call Graph")
    subprocess.run(["jelly", "-j", call_graph_path, "./"], cwd=source_code_path, timeout=600)
    if not os.path.exists(call_graph_path):
        raise JellyCallGraphGenerationError("Jelly Call Graph Generation Error due to timeout or other error")

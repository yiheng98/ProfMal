import npm_pipeline.analyser as npm_analyser
import os
import sys
from loguru import logger
from status import STATUS_CODE_MALICIOUS, STATUS_PKG_JSON_MALICIOUS


def workflow_logger_config(work_space_dir, package_name):
    # remove and add new logger config, as you can use the same logger object in different processes
    logger.remove()
    log_dir = os.path.join(work_space_dir, package_name)
    os.makedirs(log_dir, exist_ok=True)
    main_log_path = os.path.join(log_dir, "work_flow.log")
    logger.add(main_log_path, level="DEBUG", mode="w")
    logger.add(sys.stdout, level="DEBUG")


def analyse(package_name, package_dir, workspace_dir, overwrite, dynamic_support, graph_only):
    workflow_logger_config(workspace_dir, package_name)
    logger.info(f"🔍Start Analyzing Package: {package_name}")

    status_list = npm_analyser.run(
        package_name=package_name,
        package_dir=package_dir,
        workspace_dir=workspace_dir,
        overwrite=overwrite,
        dynamic_support=dynamic_support,
        graph_only=graph_only,
    )

    logger.info(f"✅Finish Analyzing Package: {package_name}")
    logger.info(f"📊Status: {status_list}")

    if status_list:
        for status in status_list:
            if status == STATUS_CODE_MALICIOUS or status == STATUS_PKG_JSON_MALICIOUS:
                return True
    return False

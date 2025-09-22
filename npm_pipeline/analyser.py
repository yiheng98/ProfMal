import os
import traceback
from status import (
    STATUS_CODE_NOT_EXIST,
    STATUS_PACKAGE_JSON_NOT_EXIST,
    STATUS_JOERN_ERROR,
    STATUS_GPT_ERROR,
    STATUS_BENIGN,
    STATUS_TIMEOUT,
    STATUS_PROGRAM_ERROR,
    STATUS_PKG_JSON_MALICIOUS,
    STATUS_CODE_MALICIOUS,
)
import signal
from npm_pipeline.classes.package_json import PackageJson
from npm_pipeline.classes.package import Package
from custom_exception import PackageJsonNotFoundException
from custom_exception import GraphReadingException
from custom_exception import JoernGenerationException
from custom_exception import NoEntryScriptException
from base_classes.report import Report
import subprocess
from loguru import logger

# the time limit of the analysis
timeout_limit = 3600


def timeout_handler(signum, frame):
    raise TimeoutError("Time out")


def timeout(seconds):
    def decorator(func):
        def wrapper(*args, **kwargs):
            # set the signal
            signal.signal(signal.SIGALRM, timeout_handler)
            # set the alarm
            signal.alarm(seconds)
            try:
                result = func(*args, **kwargs)
            finally:
                # cancel the alarm
                signal.alarm(0)
            return result

        return wrapper

    return decorator


@timeout(timeout_limit)
def run(
    package_name: str, package_dir: str, workspace_dir: str, overwrite: bool, dynamic_support: bool, graph_only: bool
):
    statuses = set()
    if not os.path.exists(package_dir):
        logger.error(f"{package_name} is not exist")
        statuses.add(STATUS_CODE_NOT_EXIST)
        return statuses
    report = Report()
    try:
        # default package.json path
        package_json_path = os.path.join(package_dir, "package", "package.json")
        if not os.path.exists(package_json_path):
            raise PackageJsonNotFoundException(package_name)

        package_json = PackageJson(package_json_path)
        mal_script = package_json.malicious_script_analysis()
        if len(mal_script) > 0:
            report.set_maliciousness_in_package_json()
            for script in mal_script:
                report.add_install_time_script(script)
        package = Package(
            package_name=package_name,
            original_package_dir=package_dir,
            workspace_dir=workspace_dir,
            package_json=package_json,
        )

        status = package.analyse(overwrite, dynamic_support, graph_only)
        statuses.add(status)

    except PackageJsonNotFoundException:
        # the package is not exist
        logger.error("Package.json is not exist")
        statuses.add(STATUS_PACKAGE_JSON_NOT_EXIST)
    except GraphReadingException as e:
        logger.error(f"Joern dot reading Error: {e}")
        statuses.add(STATUS_JOERN_ERROR)
    except ConnectionError:
        logger.error("LLM Connection error")
        statuses.add(STATUS_GPT_ERROR)
    except NoEntryScriptException:
        # the package has no entry script
        statuses.add(STATUS_BENIGN)
    except JoernGenerationException as e:
        # the file path of cpg and pdg is wrong
        logger.error(f"Joern parsing Error: {e}")
        statuses.add(STATUS_JOERN_ERROR)
    except subprocess.TimeoutExpired as e:
        # joern time out
        logger.error(f"Subprocess Time Out: {e}")
        statuses.add(STATUS_JOERN_ERROR)
    except TimeoutError:
        # program time out
        logger.error("Time Out")
        statuses.add(STATUS_TIMEOUT)
    except Exception as e:
        traceback_info = traceback.format_exc()
        logger.error("Exception occurred:")
        logger.error(e)
        logger.error(traceback_info)
        statuses.add(STATUS_PROGRAM_ERROR)

    finally:
        if report.is_maliciousness_in_package_json():
            statuses.add(STATUS_PKG_JSON_MALICIOUS)
        if report.is_maliciousness_in_code():
            statuses.add(STATUS_CODE_MALICIOUS)
        return list(statuses)

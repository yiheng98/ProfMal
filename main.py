import os
from analyse import analyse

if __name__ == "__main__":
    package_name = "The name of the package, e.g. test_package"
    # package source code
    package_dir = "The path of the package, e.g. ./packages/test_package"
    # workspace for a one package
    workspace_dir = "The path of the workspace, e.g. ./workspace"
    # overwrite the existing joern output
    overwrite = False
    # dynamic support
    dynamic_support = True
    # True: Only generate graph, False: Detect maliciousness
    graph_only = False

    analyse(package_name, package_dir, workspace_dir, overwrite, dynamic_support, graph_only)

import networkx as nx
from detector.preprocess_data import process_dot_in_memory
from detector.inference import predict_graph
from loguru import logger
import os
import traceback


def detect(dot_file_path):
    try:
        # Read the graph from dot file
        graph = nx.nx_pydot.read_dot(dot_file_path)

        # get isolated nodes
        isolated_nodes = list(nx.isolates(graph))

        # if there are isolated nodes, check their degree values
        if isolated_nodes:
            for node in isolated_nodes:
                # get the degree value from node attributes
                degree = graph.nodes[node].get("degree", 0)
                try:
                    degree = float(degree)
                except (ValueError, TypeError):
                    degree = 0
                if degree > 0.5:
                    return True

        if len(isolated_nodes) == graph.number_of_nodes():
            return False

        processed_graph = process_dot_in_memory(dot_file_path)
        if processed_graph is None:
            return False

        script_dir = os.path.dirname(os.path.abspath(__file__))
        model_path = os.path.join(script_dir, "detect_model_39.pth")

        probability = predict_graph(processed_graph, model_path)

        # If probability > 0.5, consider it malicious
        return probability > 0.5
    except Exception as e:
        logger.warning(f"Error in detect malicious graph: {e}")
        logger.warning(traceback.format_exc())
        return False

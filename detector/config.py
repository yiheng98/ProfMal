import numpy as np

node_types = [
    "Resolve DNS",
    "System Information Retrieval",
    "File Attributes Modification",
    "Data Compression",
    "Read File",
    "Environment Information Retrieval",
    "Decipher Data",
    "Cipher Data",
    "Data Decompression",
    "Write File",
    "Path Manipulation",
    "Send Data Over Network",
    "Redirect",
    "Create Directory",
    "Delete File",
    "Create Decompression Stream",
    "Copy File",
    "Network Creation",
    "Create Compression Stream",
    "Connection Establishment",
    "Open File",
    "Buffer Conversion",
    "GET Request",
    "Delete Directory",
    "Process Creation",
    "Read Directory",
    "Search File",
    "Open Directory",
    "File Execution",
    "Path Information Retrieval",
    "Create Decipher",
    "File Existence Check",
    "Create File Stream",
    "Network Information Retrieval",
    "Command Execution",
    "Create Cipher",
    "Runtime Evaluation",
    "Network Manipulation",
]

allowed_relation_types = {"Control_Flow", "Data_Flow"}

metas = []
num_node_types = len(node_types)
for target in range(num_node_types):
    for source in range(num_node_types):
        for rel in allowed_relation_types:
            # 添加正向 meta 关系（target, source, rel）
            metas.append((target, source, rel))

            # 添加反向 meta 关系（source, target, "rev_" + rel）
            metas.append((source, target, "rev_" + rel))

# 针对每个 meta 关系分配一个唯一的整型 id
meta2id = {meta: idx for idx, meta in enumerate(metas)}

node_type2id = {node_type: idx for idx, node_type in enumerate(node_types)}

id2meta = {idx: meta for meta, idx in meta2id.items()}

type_to_idx = {t: idx for idx, t in enumerate(node_types)}


def one_hot_encoding(sample_type):
    vector = np.zeros(len(node_types))
    idx = type_to_idx.get(sample_type)
    if idx is not None:
        vector[idx] = 1
    return vector

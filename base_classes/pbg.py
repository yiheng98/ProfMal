import json

from base_classes.pdg_node import PDGNode
from base_classes.cpg import CPG
from base_classes.pdg import PDG
from base_classes.cpg_pdg_edge import Edge
from npm_pipeline.classes.object import Object
import networkx as nx
from npm_pipeline.classes.code_Info import CodeInfo
from collections import deque
from sensitive_op import sensitive_call_finder
from sensitive_op import sensitive_property_access_finder
import sensitive_degree_helper


class PBG:
    """
    record the behavior of the program
    """

    def __init__(self, cpg: CPG, pdg_dict: dict[int, PDG], package_dir, package_name):
        self.entrance_node = None  # pbg的入口节点
        self.return_node: list[PDGNode] = []  # 记录pbg的返回结果
        self.pdg_nodes: dict[int, PDGNode] = {}
        self.pdg_edges: dict[tuple[int, int], Edge] = {}
        self.pdg_out_edges: dict[int, set[int]] = {}
        self.pdg_in_edges: dict[int, set[int]] = {}
        self.object_nodes: list[Object] = []
        self.pdg_object_data_edge: dict[int, set[Object]] = {}  # 记录pdg到object之间的数据流边
        self.object_pdg_data_edge: dict[Object, set[int]] = {}  # 记录记录Object到pdg之间的数据流边
        self.cpg = cpg
        self.pdg_dict = pdg_dict
        self.package_dir = package_dir
        self.package_name = package_name
        self.sensitive_graph = None
        self.visited = []

    def extract_sensitive_subgraph(self, code_info: CodeInfo):
        node_id_list = list(self.pdg_nodes.keys())
        sensitive_node_list = []
        for node_id in node_id_list:
            pdg_node = self.pdg_nodes[node_id]
            if pdg_node.is_sensitive_node():
                sensitive_node_list.append(pdg_node)

        G = self.create_networkx_graph()
        sensitive_nodes = [n for n, data in G.nodes(data=True) if data.get('color') == 'red']
        subG = nx.MultiDiGraph()
        for n in sensitive_nodes:
            subG.add_node(n, **G.nodes[n])
            subG.nodes[n]['color'] = 'black'

        for u in sensitive_nodes:
            # 查找最近敏感节点，只用DDG，并添加 Data_Flow 边
            v_list_data = self.find_next_sensitive_nodes(G, u, sensitive_nodes, label_filter={'DDG'})
            for v in v_list_data:
                # 如果子图里还没有 (u->v) 的边，则添加
                if not subG.has_edge(u, v):
                    subG.add_edge(u, v, label='Data_Flow', color='red')

            # 查找最近敏感节点，只用CFG，并添加 Control_Flow 边
            v_list_cfg = self.find_next_sensitive_nodes(G, u, sensitive_nodes, label_filter={'CFG'})
            for v in v_list_cfg:
                has_cf_edge = False

                # 如果已存在多重边，则检查是否有 label='Control_Flow'
                if subG.has_edge(u, v):
                    edge_data_dict = subG.get_edge_data(u, v)
                    for _, edge_attrs in edge_data_dict.items():
                        if edge_attrs.get('label') == 'Control_Flow':
                            has_cf_edge = True
                            break

                # 若尚无 "Control_Flow" 类型的边，则添加
                if not has_cf_edge:
                    subG.add_edge(u, v, label='Control_Flow', color='blue')

            # 查找最近敏感节点，分析基于数据流，并且满足CFG的顺序
            v_list_obj = self.find_next_sensitive_nodes_object_cfg_forward(G, u, sensitive_nodes)
            for v in v_list_obj:
                has_dd_edge = False
                if subG.has_edge(u, v):
                    edge_data_dict = subG.get_edge_data(u, v)
                    for _, edge_attrs in edge_data_dict.items():
                        if edge_attrs.get('label') == 'Data_Flow':
                            has_dd_edge = True
                            break

                if not has_dd_edge:
                    subG.add_edge(u, v, label='Data_Flow', color='red')

        # 对每对敏感节点 (u, v) 做额外判断
        # 如果 CFG 上互相不可达，但有共同祖先，就判断的是否存在Object_Data边的联系
        sens_list = list(sensitive_nodes)
        for i in range(len(sens_list)):
            for j in range(i + 1, len(sens_list)):
                u = sens_list[i]
                v = sens_list[j]
                # 如果在 CFG 上既没有 u->v 也没有 v->u
                if not self.has_cfg_path(G, u, v) and not self.has_cfg_path(G, v, u):
                    # 再判断是否有共同祖先
                    if self.has_common_cfg_ancestor(G, u, v):
                        # 如果有共同祖先
                        if self.has_data_flow_path(G, u, v, sens_list, data_labels={'Object_Data', 'DDG'}):
                            if not subG.has_edge(u, v):
                                # 如果有，就在子图里加一条 (u->v) 的数据流边
                                subG.add_edge(u, v, label='Data_Flow', color='red')

        if code_info.api_call_info is not None:
            # under dynamic analysis
            recorded_mapping = code_info.api_call_to_pdg_node_mapping

            # find missing API
            missing_indices = []
            for idx, api_call in enumerate(code_info.api_call_info.collections):
                if api_call not in recorded_mapping and self.is_sensitive(api_call):
                    missing_indices.append(idx)

            # Group successive missing API calls into a group
            groups = []
            current_group = []
            for i in missing_indices:
                if not current_group or i == current_group[-1] + 1:
                    current_group.append(i)
                else:
                    groups.append(current_group)
                    current_group = [i]
            if current_group:
                groups.append(current_group)

            for group in groups:
                first_missing_idx = group[0]
                last_missing_idx = group[-1]

                # 从 first_missing_idx 向前找最近的已记录 API 调用对应的 PDG 节点
                prev_recorded = None
                for i in range(first_missing_idx - 1, -1, -1):
                    candidate_api = code_info.api_call_info.collections[i]
                    if candidate_api in recorded_mapping:
                        prev_recorded = recorded_mapping[candidate_api]
                        break

                next_recorded = None
                for i in range(last_missing_idx + 1, len(code_info.api_call_info.collections)):
                    candidate_api = code_info.api_call_info.collections[i]
                    if candidate_api in recorded_mapping:
                        next_recorded = recorded_mapping[candidate_api]
                        break

                # 依次为组内每个缺失 API 调用创建新节点并插入到 subG 中
                previous_node = prev_recorded  # 初始时，前一个节点为前边界（可能为 None）
                for missing_idx in group:
                    api_call = code_info.api_call_info.collections[missing_idx]
                    if api_call.type == 'function':
                        sensitive_info = sensitive_call_finder.query(f"{api_call.module}.{api_call.function}")
                    else:
                        sensitive_info = sensitive_property_access_finder.query(
                            f"{api_call.module}.{api_call.function}")

                    if sensitive_info['domain'] == 'Process':
                        degree = sensitive_degree_helper.get_subprocess_sensitivity_degree(sensitive_info['full_name'],
                                                                                           api_call.arguments)
                    elif sensitive_info['domain'] == 'File':
                        degree = sensitive_degree_helper.get_file_sensitivity_degree(sensitive_info['full_name'],
                                                                                     api_call.arguments,
                                                                                     api_call.result)
                    else:
                        degree = 0.5

                    # 生成唯一的新节点 ID，例如：missing_api_索引
                    new_node_id = f"missing_api_{missing_idx}"
                    # 设置新节点属性，可以根据需要调整
                    node_attr = {
                        "label": f"{api_call.module}.{api_call.function}",
                        "color": "black",
                        "full_name": sensitive_info['full_name'],
                        "domain": sensitive_info['domain'],
                        "degree": degree
                    }
                    subG.add_node(new_node_id, **node_attr)
                    # 如果前边界或上一个插入的缺失节点存在，则添加 Control Flow 边
                    if previous_node is not None:
                        subG.add_edge(previous_node, new_node_id, label="Control_Flow")
                        # subG.add_edge(previous_node, new_node_id, label="Data_Flow")
                    previous_node = new_node_id

                # 如果后边界存在，则将组内最后一个新节点与后边界连接
                if next_recorded is not None and previous_node is not None:
                    subG.add_edge(previous_node, next_recorded, label="Control_Flow")
                    # subG.add_edge(previous_node, next_recorded, label="Data_Flow")

        return subG

    @staticmethod
    def has_cfg_path(G, start, end):
        """Find the node from start to end has cfg path"""
        visited = set()
        queue = deque([start])

        while queue:
            cur = queue.popleft()
            if cur == end:
                return True
            for nxt in G.successors(cur):
                if nxt not in visited:
                    edge_data_dict = G.get_edge_data(cur, nxt, default={})
                    for _, attrs in edge_data_dict.items():
                        if attrs.get('label') == 'CFG':
                            visited.add(nxt)
                            queue.append(nxt)
                            break
        return False

    @staticmethod
    def has_data_flow_path(G, start, end, sensitive_list, data_labels):
        """
        判断是否存在从 start 到 end 的“数据流”路径，
        只使用 label ∈ data_labels 的有向边来遍历。

        若能在有向图 G 中沿着这些标签走到 end，返回 True，否则 False。
        """
        from collections import deque
        visited = set()
        queue = deque([start])
        visited.add(start)

        while queue:
            cur = queue.popleft()
            if cur == end:
                return True

            for nxt in G.successors(cur):
                if nxt not in visited:
                    if nxt in sensitive_list and nxt != end:
                        visited.add(nxt)
                        continue
                    edge_data_dict = G.get_edge_data(cur, nxt, default={})
                    # 只要并行边中有一条的 label ∈ data_labels 即可前进
                    for _, attrs in edge_data_dict.items():
                        if attrs.get('label') in data_labels:
                            visited.add(nxt)
                            queue.append(nxt)
                            break
        return False

    @staticmethod
    def get_cfg_ancestors(G, node):
        """
        沿着label=CFG的边反向搜索，获取node的祖先节点
        """
        ancestors = {node}
        queue = deque([node])

        while queue:
            cur = queue.popleft()
            for pre in G.predecessors(cur):
                if pre not in ancestors:
                    edge_data_dict = G.get_edge_data(pre, cur, default={})
                    for _, attrs in edge_data_dict.items():
                        if attrs.get('label') == 'CFG':
                            ancestors.add(pre)
                            queue.append(pre)
                            break
        return ancestors

    def has_common_cfg_ancestor(self, G, n1, n2):
        """Judge the node n1 and n2 has the same ancestor"""
        anc1 = self.get_cfg_ancestors(G, n1)
        anc2 = self.get_cfg_ancestors(G, n2)
        return len(anc1.intersection(anc2)) > 0

    @staticmethod
    def get_reachable_nodes(G, source, label):
        """
        Returns the set of nodes reachable from `source` by following
        edges whose "label" attribute matches the passed `label`.
        """
        reachable = {source}
        queue = deque([source])

        while queue:
            cur = queue.popleft()
            for nxt in G.successors(cur):
                # Only explore nxt if it hasn't been visited yet
                if nxt not in reachable:
                    edge_data_dict = G.get_edge_data(cur, nxt, default={})
                    for _, attrs in edge_data_dict.items():
                        # If this edge has the matching label, traverse it
                        if attrs.get('label') in label:
                            reachable.add(nxt)
                            queue.append(nxt)
                            # Break here so we don't consider multiple edges
                            # to the same successor
                            break

        return reachable

    @staticmethod
    def find_next_sensitive_nodes(G, source, sensitive_nodes, label_filter):
        """
        在图 G 中，以 source 为起点，只能走 label ∈ label_filter 的有向边；
        遇到的第一个（或多个）敏感节点即为“最近”敏感节点。
        在搜索过程中，若 path 上出现其他敏感节点 (≠ source) 则终止该分支，

        返回一个列表，表示所有可能的“同层”最近敏感节点
        若找不到则返回空列表。
        """

        queue = deque([source])
        visited = {source}
        found_sensitive = []

        while queue:
            level_size = len(queue)
            level_nodes = [queue.popleft() for _ in range(level_size)]
            next_layer = []
            for current in level_nodes:
                for nxt in G.successors(current):
                    if nxt not in visited:
                        edge_data_dict = G.get_edge_data(current, nxt, default={})
                        for _, eattrs in edge_data_dict.items():
                            if eattrs.get('label', '') in label_filter:
                                visited.add(nxt)
                                next_layer.append(nxt)
                                break

            new_found = [n for n in next_layer if n != source and n in sensitive_nodes]
            found_sensitive.extend(new_found)
            remaining_nodes = [n for n in next_layer if n not in new_found]
            queue.extend(remaining_nodes)

        return found_sensitive

    def find_next_sensitive_nodes_object_cfg_forward(self, G, source, sensitive_nodes):
        cfg_reachable = self.get_reachable_nodes(G, source, {'CFG'})

        queue = deque([source])
        visited = {source}
        found_sensitive = []

        while queue:
            level_size = len(queue)
            level_nodes = [queue.popleft() for _ in range(level_size)]
            next_layer = []
            for current in level_nodes:
                for nxt in G.successors(current):
                    if nxt not in visited:
                        edge_data_dict = G.get_edge_data(current, nxt, default={})
                        for _, eattrs in edge_data_dict.items():
                            if eattrs.get('label', '') in {'Object_Data', 'DDG'}:
                                visited.add(nxt)
                                next_layer.append(nxt)
                                break

            new_found = [n for n in next_layer if n != source and n in sensitive_nodes and n in cfg_reachable]
            found_sensitive.extend(new_found)
            remaining_nodes = [n for n in next_layer if n not in new_found]
            queue.extend(remaining_nodes)

        return found_sensitive

    def create_networkx_graph(self):
        G = nx.MultiDiGraph()
        for node_id in self.pdg_nodes.keys():
            pdg_node = self.pdg_nodes[node_id]
            if pdg_node.is_sensitive_node():
                color = 'red'
            else:
                color = 'black'
            if pdg_node.get_node_type() == 'METHOD':
                G.add_node(node_id, color='blue',
                           label=f"{node_id}, {pdg_node.get_line_number()}, {pdg_node.get_name()}\n")
            else:
                if color == 'red':
                    G.add_node(node_id, color=color,
                               label=f"{node_id}, {pdg_node.get_line_number()}, {pdg_node.get_name()}\n"
                                     f"{pdg_node.get_sensitive_dict()['full_name']}",
                               full_name=pdg_node.get_sensitive_dict()['full_name'],
                               domain=pdg_node.get_sensitive_dict()['domain'],
                               degree=pdg_node.get_sensitive_degree()
                               )
                else:
                    G.add_node(node_id, color=color,
                               label=f"{node_id}, {pdg_node.get_line_number()}, {pdg_node.get_name()}\n")

        for head, tails in self.pdg_out_edges.items():
            for tail in tails:
                pdg_edge = self.pdg_edges[(head, tail)]
                pdg_edge_type = self.get_type_of_edge(pdg_edge)
                if pdg_edge_type == 'CFG':
                    G.add_edge(head, tail, label=pdg_edge_type)
                elif pdg_edge_type == 'DDG':
                    G.add_edge(head, tail, label=pdg_edge_type, color='red')
                elif pdg_edge_type == 'CFG_DDG':
                    G.add_edge(head, tail, label='CFG')
                    G.add_edge(head, tail, label='DDG', color='red')
                elif pdg_edge_type == 'REMOVE':
                    pass
                else:
                    G.add_edge(head, tail, label=pdg_edge_type)

        for _object in self.object_nodes:
            G.add_node(_object.get_name(), label=f"{_object.get_name()}\n")

        for head, ref_object_set in self.pdg_object_data_edge.items():
            for ref_object in ref_object_set:
                G.add_edge(head, ref_object.get_name(), label='Object_Data', color='red')

        for ref_object, tails in self.object_pdg_data_edge.items():
            for tail in tails:
                G.add_edge(ref_object.get_name(), tail, label='Object_Data', color='red')

        isolates = list(nx.isolates(G))

        # 删除这些孤立节点
        G.remove_nodes_from(isolates)
        return G

    def pdg_to_dot(self):
        G = self.create_networkx_graph()
        return G

    def add_object(self, ref_object: Object):
        if ref_object in self.object_nodes:
            # the object is already there, skip
            return
        else:
            self.object_nodes.append(ref_object)

    def add_pdg_to_object_data_edge(self, pdg_node_id: int, ref_object: Object):
        """
        add the data edge from the pdg to the Object
        """
        if pdg_node_id in self.pdg_object_data_edge:
            self.pdg_object_data_edge[pdg_node_id].add(ref_object)
        else:
            self.pdg_object_data_edge[pdg_node_id] = set()
            self.pdg_object_data_edge[pdg_node_id].add(ref_object)

    def add_object_to_pdg_edge(self, ref_object: Object, pdg_node_id: int):
        """
        add the data edge from the Object to the pdg node
        """
        if ref_object not in self.object_nodes:
            self.add_object(ref_object)
        if ref_object in self.object_pdg_data_edge:
            self.object_pdg_data_edge[ref_object].add(pdg_node_id)
        else:
            self.object_pdg_data_edge[ref_object] = set()
            self.object_pdg_data_edge[ref_object].add(pdg_node_id)

    def add_pdg_node(self, node: PDGNode):
        """
        向result中添加新的点
        """
        self.pdg_nodes[node.get_id()] = node

    def add_pdg_edge(self, head: int, tail: int, edge_attr: list):
        """
        add edge to the program behavior graph
        """
        if head in self.pdg_out_edges and tail in self.pdg_out_edges[head]:
            # the edge is already there, update edge attr
            for attr in edge_attr:
                if attr not in self.pdg_edges[(head, tail)].get_attr():
                    self.pdg_edges[(head, tail)].add_attr(attr)
        if (head, tail) not in self.pdg_edges:

            # 创建新的边实例
            edge = Edge((head, tail))
            for attr in edge_attr:
                edge.add_attr(attr)
            self.pdg_edges[(head, tail)] = edge
        if head in self.pdg_out_edges:
            self.pdg_out_edges[head].add(tail)
        else:
            self.pdg_out_edges[head] = set()
            self.pdg_out_edges[head].add(tail)

        if tail in self.pdg_in_edges:
            self.pdg_in_edges[tail].add(head)
        else:
            self.pdg_in_edges[tail] = set()
            self.pdg_in_edges[tail].add(head)

    @staticmethod
    def is_sensitive(api_call):
        if api_call.type == 'function':
            return sensitive_call_finder.query(f"{api_call.module}.{api_call.function}")
        else:
            return sensitive_property_access_finder.query(f"{api_call.module}.{api_call.function}")

    def get_pdg_out_edges(self) -> dict[int, set[int]]:
        return self.pdg_out_edges

    def get_pdg_in_edges(self) -> dict[int, set[int]]:
        return self.pdg_in_edges

    def pdg_node_is_in(self, node: PDGNode):
        return node.get_id() in self.pdg_nodes

    def set_entrance_node(self, node: PDGNode):
        self.entrance_node = node

    def get_entrance_node(self) -> PDGNode:
        return self.entrance_node

    def add_return_node(self, node: PDGNode):
        self.return_node.append(node)

    def get_return_value(self) -> list[PDGNode]:
        return self.return_node

    def get_pdg_nodes(self) -> dict[int, PDGNode]:
        return self.pdg_nodes

    def get_object_nodes(self) -> list[Object]:
        return self.object_nodes

    def get_pdg_object_data_edge(self) -> dict[int, set[Object]]:
        return self.pdg_object_data_edge

    def get_object_pdg_data_edge(self) -> dict[Object, set[int]]:
        return self.object_pdg_data_edge

    def get_pdg_edges(self) -> dict[tuple[int, int], Edge]:
        return self.pdg_edges

    def add_batch_object_nodes(self, nodes: list[Object]):
        for node in nodes:
            if node not in self.object_nodes:
                self.object_nodes.append(node)

    def add_batch_pdg_object_data_edge(self, edges: dict[int, set[Object]]):
        for key, value in edges.items():
            if key not in self.pdg_object_data_edge:
                self.pdg_object_data_edge[key] = value
            else:
                self.pdg_object_data_edge[key].update(value)

    def add_batch_object_pdg_data_edge(self, edges: dict[Object, set[int]]):
        for key, value in edges.items():
            if key not in self.object_pdg_data_edge:
                self.object_pdg_data_edge[key] = value
            else:
                self.object_pdg_data_edge[key].update(value)

    def add_batch_pdg_nodes(self, nodes: dict[int, PDGNode]):
        for key, value in nodes.items():
            if key not in self.pdg_nodes:
                self.pdg_nodes[key] = value

    def add_batch_pdg_edges(self, edges: dict[tuple[int, int], Edge]):
        for key, value in edges.items():
            if key not in self.pdg_edges:
                self.pdg_edges[key] = value

    def add_batch_pdg_in_edges(self, in_edges: dict[int, set[int]]):
        for key, value in in_edges.items():
            if key not in self.pdg_in_edges:
                self.pdg_in_edges[key] = value
            else:
                self.pdg_in_edges[key].update(value)

    def add_batch_pdg_out_edges(self, out_edges: dict[int, set[int]]):
        for key, value in out_edges.items():
            if key not in self.pdg_out_edges:
                self.pdg_out_edges[key] = value
            else:
                self.pdg_out_edges[key].update(value)

    @staticmethod
    def get_type_of_edge(edge: Edge):
        contain_ddg = False
        contain_cfg = False
        contain_remove = False
        attr_list = edge.get_attr()
        for attr in attr_list:
            if 'REMOVE' in attr:
                contain_remove = True
            if 'DDG' in attr:
                contain_ddg = True
            if 'CFG' in attr:
                contain_cfg = True
        # If REMOVE is present, treat it as a higher-priority label.
        if contain_ddg and contain_cfg:
            return 'CFG_DDG'
        elif contain_ddg:
            return "DDG"
        elif contain_cfg:
            return 'CFG'
        elif contain_remove:
            return 'REMOVE'
        else:
            return 'CFG'

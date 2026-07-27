from core.state_store import StateStore


class AttackGraph:
    def __init__(self, store: StateStore):
        self.store = store

    def add_node(self, engagement_id: str, key: str,
                 node_type: str, attributes: dict):
        self.store.add_graph_node(engagement_id, key, node_type, attributes)

    def add_edge(self, engagement_id: str, source: str,
                 target: str, rel_type: str):
        self.store.add_graph_edge(engagement_id, source, target, rel_type)

    def get_node(self, engagement_id: str, key: str) -> dict | None:
        return self.store.get_graph_node(engagement_id, key)

    def get_neighbors(self, engagement_id: str,
                      key: str) -> list[tuple[str, str]]:
        return self.store.get_graph_neighbors(engagement_id, key)

    def get_filtered_context(self, engagement_id: str,
                             active_node_key: str) -> dict:
        """Traverse graph up to 2 hops from the active node to filter context."""
        visited_nodes = {}
        edges_to_include = []

        # 2-hop Breadth-First-Search (BFS) traversal
        queue = [(active_node_key, 0)]
        while queue:
            node, depth = queue.pop(0)
            if node not in visited_nodes and depth <= 2:
                node_data = self.get_node(engagement_id, node)
                if node_data:
                    visited_nodes[node] = node_data
                    for neighbor, rel_type in self.get_neighbors(
                            engagement_id, node):
                        edges_to_include.append((node, neighbor, rel_type))
                        queue.append((neighbor, depth + 1))

        return {"nodes": visited_nodes, "edges": edges_to_include}

    def get_dependencies(self, engagement_id: str, key: str) -> list[str]:
        """Get all nodes that this node REQUIRES."""
        return [n for n, rel in self.get_neighbors(
            engagement_id, key) if rel == "REQUIRES"]

    def get_dependents(self, engagement_id: str, key: str) -> list[str]:
        """Get all nodes that this node LEADS_TO."""
        return [n for n, rel in self.get_neighbors(
            engagement_id, key) if rel == "LEADS_TO"]

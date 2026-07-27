import unittest
from core.attack_graph import AttackGraph
from core.state_store import StateStore


class TestGraphTraversal(unittest.TestCase):
    def setUp(self):
        self.store = StateStore(":memory:")
        self.graph = AttackGraph(self.store)
        self.eng_id = "test_engagement"

        self.graph.add_node(self.eng_id, "10.0.0.1", "host", {})
        self.graph.add_node(self.eng_id, "10.0.0.2", "host", {})
        self.graph.add_node(self.eng_id, "10.0.0.3", "host", {})

        self.graph.add_edge(self.eng_id, "10.0.0.1", "10.0.0.2", "can_reach")
        self.graph.add_edge(self.eng_id, "10.0.0.2", "10.0.0.3", "can_reach")

    def test_get_filtered_context(self):
        ctx = self.graph.get_filtered_context(self.eng_id, "10.0.0.1")
        # In V7, get_filtered_context is hardcoded to depth=2
        # So we should see all 3 nodes
        self.assertIn("10.0.0.1", ctx["nodes"])
        self.assertIn("10.0.0.2", ctx["nodes"])
        self.assertIn("10.0.0.3", ctx["nodes"])


if __name__ == '__main__':
    unittest.main()

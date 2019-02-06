
from appscale.agents.factory import InfrastructureAgentFactory

try:
    from unittest import TestCase
except ImportError:
    from unittest.case import TestCase


class TestBaseAgent(TestCase):

    def setUp(self):
        self.factory = InfrastructureAgentFactory()

    def test_diff_helper(self):
        agent = self.factory.create_agent('euca')
        list1 = [1,2,3,4,5]
        list2 = [3,5,6]
        expected = [1,2,4]
        actual = agent.diff(list1, list2)
        self.assertListEqual(expected, actual)

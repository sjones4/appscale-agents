from appscale.agents.ec2_agent import EC2Agent
from appscale.agents.euca_agent import EucalyptusAgent
from appscale.agents.azure_agent import AzureAgent
from appscale.agents.gce_agent import GCEAgent
from appscale.agents.openstack_agent import OpenStackAgent

from appscale.agents.factory import InfrastructureAgentFactory
from appscale.agents.agent_exceptions import UnknownInfrastructureException

try:
    from unittest import TestCase
except ImportError:
    from unittest.case import TestCase


class TestAgentFactory(TestCase):

    def setUp(self):
        self.factory = InfrastructureAgentFactory()

    def test_create_agent_ec2(self):
        agent = self.factory.create_agent('ec2')
        self.assertIsInstance(agent, EC2Agent)

    def test_create_agent_euca(self):
        agent = self.factory.create_agent('euca')
        self.assertIsInstance(agent, EucalyptusAgent)

    def test_create_agent_azure(self):
        agent = self.factory.create_agent('azure')
        self.assertIsInstance(agent, AzureAgent)

    def test_create_agent_gce(self):
        agent = self.factory.create_agent('gce')
        self.assertIsInstance(agent, GCEAgent)

    def test_create_agent_openstack(self):
        agent = self.factory.create_agent('openstack')
        self.assertIsInstance(agent, OpenStackAgent)

    def test_create_invalid_infrastructure(self):
        """
        Ensure that the correct exception is thrown if the create_agent method is
        given an invalid parameter (agent)
        """
        self.assertRaises(UnknownInfrastructureException, self.factory.create_agent, 'BOGUS')

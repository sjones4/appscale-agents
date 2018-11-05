import boto
import boto.ec2
import time

from appscale.agents.base_agent import AgentRuntimeException
from appscale.agents.base_agent import AgentConfigurationException
from boto.ec2.spotpricehistory import SpotPriceHistory
from boto.ec2.instance import Reservation
from boto.ec2.keypair import KeyPair
from boto.ec2.securitygroup import SecurityGroup
from boto.exception import EC2ResponseError
from flexmock import flexmock

from appscale.agents.factory import InfrastructureAgentFactory

try:
    from unittest import TestCase
except ImportError:
    from unittest.case import TestCase


class TestEC2Agent(TestCase):

    def test_ec2_run_instances(self):
        self.run_instances('ec2', True)
        self.run_instances('ec2', False)

    def test_ec2_run_instances_agentruntimeexception(self):
        e = AgentRuntimeException('Mock error')
        self.fake_ec2.should_receive('run_instances').and_raise(e)

        self.assertRaises(AgentRuntimeException, self.run_instances, 'ec2', True, False)

    def spot_price(self, price, ts):
        spot_price = SpotPriceHistory()
        spot_price.price = price
        spot_price.timestamp = ts
        return spot_price

    def run_instances(self, prefix, blocking, success=True):
        i = self.factory.create_agent('ec2')
        reservation = Reservation()
        instance = flexmock(name='instance', private_dns_name='private-ip',
                            public_dns_name='public-ip', id='i-id', state='running',
                            key_name='bookeyname', ip_address='public-ip',
                            private_ip_address='private-ip')
        new_instance = flexmock(name='new-instance', private_dns_name='new-private-ip',
                                public_dns_name='new-public-ip', id='new-i-id',
                                state='running', key_name='bookeyname',
                                ip_address='new-public-ip',
                                private_ip_address='new-private-ip')
        reservation.instances = [instance]
        new_reservation = Reservation()
        new_reservation.instances = [instance, new_instance]
        if success:
            self.fake_ec2.should_receive('get_all_instances').and_return([]) \
                .and_return([reservation]).and_return([reservation]) \
                .and_return([new_reservation]).and_return([new_reservation])
        else:
            self.fake_ec2.should_receive('get_all_instances') \
                .and_return([reservation])

        # first, validate that the run_instances call goes through successfully
        # and gives the user a operation id
        full_params = {
            'credentials': {
                'a': 'b', 'EC2_URL': 'http://testing.appscale.com:8773/foo/bar',
                'EC2_ACCESS_KEY': 'access_key', 'EC2_SECRET_KEY': 'secret_key'},
            'group': 'boogroup',
            'image_id': 'booid',
            'infrastructure': prefix,
            'instance_type': 'booinstance_type',
            'keyname': 'bookeyname',
            'num_vms': '1',
            'use_spot_instances': False,
            'region': 'my-zone-1',
            'zone': 'my-zone-1b',
            'autoscale_agent': True
        }

        id = '0000000000'  # no longer randomly generated

        agent_run_instances_result = (['new-i-id'],
                                      ['new-public-ip'],
                                      ['new-private-ip'])
        security_configured = i.configure_instance_security(full_params)

        self.assertTupleEqual(agent_run_instances_result,
                              i.run_instances(int(full_params['num_vms']),
                                              full_params,
                                              security_configured,
                                              public_ip_needed=False))

    def setUp(self):
        self.factory = InfrastructureAgentFactory()

        self.fake_ec2 = flexmock(name='self.fake_ec2')
        self.fake_ec2.should_receive('get_key_pair')
        self.fake_ec2.should_receive('create_key_pair').with_args('bookeyname') \
            .and_return(KeyPair())
        self.fake_ec2.should_receive('get_all_security_groups').and_return([])
        self.fake_ec2.should_receive('create_security_group') \
            .with_args('boogroup', 'AppScale security group') \
            .and_return(SecurityGroup())
        self.fake_ec2.should_receive('authorize_security_group')

        instance = flexmock(name='instance', private_dns_name='private-ip',
                            public_dns_name='public-ip', id='i-id', state='running',
                            key_name='bookeyname')

        self.fake_ec2.should_receive('terminate_instances').and_return([instance])
        self.fake_ec2.should_receive('run_instances')

        flexmock(boto.ec2)
        boto.ec2.should_receive('connect_to_region').and_return(self.fake_ec2)

    def tearDown(self):
        pass

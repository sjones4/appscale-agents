from boto.ec2.connection import EC2Connection
from boto.ec2.instance import Reservation, Instance
from boto.ec2.keypair import KeyPair
from boto.ec2.securitygroup import SecurityGroup
from flexmock import flexmock

from appscale.agents.factory import InfrastructureAgentFactory

try:
    from unittest import TestCase
except ImportError:
    from unittest.case import TestCase


class TestEucaAgent(TestCase):

    def test_euca_run_instances(self):
        i = self.factory.create_agent('euca')

        reservation = Reservation()
        instance = flexmock(name='instance', private_dns_name='private-ip',
                            public_dns_name='public-ip', id='i-id', state='running',
                            key_name='bookeyname', ip_address='public-ip',
                            private_ip_address='private-ip')
        new_instance = flexmock(name='new-instance', private_dns_name='new-private-ip',
                                public_dns_name='new-public-ip', id='new-i-id', state='running',
                                key_name='bookeyname', ip_address='new-public-ip',
                                private_ip_address='new-private-ip')
        reservation.instances = [instance]
        new_reservation = Reservation()
        new_reservation.instances = [instance, new_instance]
        flexmock(EC2Connection).should_receive('get_all_instances').and_return([]) \
            .and_return([reservation]).and_return([reservation]) \
            .and_return([new_reservation]).and_return([new_reservation])

        # first, validate that the run_instances call goes through successfully
        # and gives the user an operation id
        full_params = {
            'credentials': {
                'a': 'b', 'EC2_URL': 'http://testing.appscale.com:8773/foo/bar',
                'EC2_ACCESS_KEY': 'access_key', 'EC2_SECRET_KEY': 'secret_key'},
            'group': 'boogroup',
            'image_id': 'booid',
            'infrastructure': 'euca',
            'instance_type': 'booinstance_type',
            'keyname': 'bookeyname',
            'num_vms': '1',
            'use_spot_instances': False,
            'zone': 'my-zone-1b',
            'autoscale_agent': True,
            'IS_VERBOSE': True
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

        (flexmock(EC2Connection)
         .should_receive('get_key_pair')
         .and_return(None))
        (flexmock(EC2Connection)
         .should_receive('create_key_pair')
         .with_args('bookeyname')
         .and_return(KeyPair()))
        (flexmock(EC2Connection)
         .should_receive('get_all_security_groups')
         .and_return([]))
        (flexmock(EC2Connection)
         .should_receive('create_security_group')
         .with_args('boogroup', 'AppScale security group')
         .and_return(SecurityGroup()))
        (flexmock(EC2Connection)
         .should_receive('authorize_security_group')
         .and_return())
        (flexmock(EC2Connection)
         .should_receive('run_instances')
         .and_return())

    def tearDown(self):
        pass

import boto
import boto.ec2
import sys
import logging

from appscale.agents.base_agent import AgentRuntimeException
from appscale.agents.base_agent import AgentConfigurationException
from boto.ec2.spotpricehistory import SpotPriceHistory
from boto.ec2.instance import Reservation
from boto.ec2.keypair import KeyPair
from boto.ec2.securitygroup import SecurityGroup
from boto.exception import EC2ResponseError
from flexmock import flexmock

from appscale.agents.factory import InfrastructureAgentFactory
from appscale.agents.ec2_agent import InvalidFilter, InstanceIDNotFound

try:
    from unittest import TestCase
except ImportError:
    from unittest.case import TestCase


class TestEC2AgentStatusChange(TestCase):
    """
    Test cases that test out the ec2agent.wait_for_status_change() method and how
    it handles the cases where an instance id is not found.
    """
    def setUp(self):
        self.factory = InfrastructureAgentFactory()
        self.fake_ec2 = flexmock(name='self.fake_ec2')
        flexmock(boto.ec2)
        boto.ec2.should_receive('connect_to_region').and_return(self.fake_ec2)

        reservation = Reservation()
        instance = flexmock(name='instance', private_dns_name='private-ip',
                            public_dns_name='public-ip', id='i-aabbccee', state='running',
                            key_name='bookeyname', ip_address='public-ip',
                            private_ip_address='private-ip')
        new_instance = flexmock(name='new-instance', private_dns_name='new-private-ip',
                                public_dns_name='new-public-ip', id='i-aabbccff',
                                state='running', key_name='bookeyname',
                                ip_address='new-public-ip',
                                private_ip_address='new-private-ip')

        t_aabbccee = flexmock(name='instance', private_dns_name='private-ip',
                              public_dns_name='public-ip', id='i-aabbccee', state='terminated',
                              key_name='bookeyname', ip_address='public-ip',
                              private_ip_address='private-ip')
        t_aabbccff = flexmock(name='new-instance', private_dns_name='new-private-ip',
                              public_dns_name='new-public-ip', id='i-aabbccff',
                              state='terminated', key_name='bookeyname',
                              ip_address='new-public-ip',
                              private_ip_address='new-private-ip')
        t_aabbccdd = flexmock(name='instance', private_dns_name='private-ip',
                              public_dns_name='public-ip', id='i-aabbccdd', state='terminated',
                              key_name='bookeyname', ip_address='public-ip',
                              private_ip_address='private-ip')

        reservation.instances = [instance]
        new_reservation = Reservation()
        new_reservation.instances = [instance, new_instance]

        # For testing wait_for_status
        self.good_reservation = Reservation()
        self.good_reservation.instances = [instance, new_instance]
        self.good_reservations = [self.good_reservation]
        self.terminated_reservation = Reservation()

        # Used because we filter for 'terminated' and it should return no instances..
        self.empty_reservation = Reservation()
        self.empty_reservation.instances = []
        self.empty_reservations = [self.empty_reservation]

        self.terminated_reservation.instances = [t_aabbccee, t_aabbccff, t_aabbccdd]
        self.terminated_reservations = [self.terminated_reservation]

        self.instance_notfound_body = """
        <Response xmlns=""><Errors>
        <Error>
        <Code>InvalidInstanceID.NotFound</Code>
        <Message>The instance ID '{}' does not exist</Message>
        </Error></Errors>
        <RequestID>23548a3a-d6c8-4de7-b846-4e072587c582</RequestID></Response>
        """

        self.multiple_instances_not_found = """
        <Response xmlns=""><Errors>
        <Error>
        <Code>InvalidInstanceID.NotFound</Code>
        <Message>The instance IDs '{}' do not exist</Message>
        </Error></Errors>
        <RequestID>23548a3a-d6c8-4de7-b846-4e072587c582</RequestID></Response>
        """

        self.full_params = {
            'credentials': {
                'a': 'b', 'EC2_URL': 'http://testing.appscale.com:8773/foo/bar',
                'EC2_ACCESS_KEY': 'access_key', 'EC2_SECRET_KEY': 'secret_key'},
            'group': 'boogroup',
            'image_id': 'booid',
            'infrastructure': 'ec2',
            'instance_type': 'booinstance_type',
            'keyname': 'bookeyname',
            'num_vms': '1',
            'use_spot_instances': False,
            'region': 'my-zone-1',
            'zone': 'my-zone-1b',
            'autoscale_agent': True
        }

    def test_ec2_wait_for_status_change_invalid_filters(self):
        """
        Simple test case if an invalid filter is passed"
        """
        ec2 = self.factory.create_agent('ec2')
        conn = ec2.open_connection(self.full_params)
        with self.assertRaisesRegexp(InvalidFilter, 'instance-state-name is missing from filter'):
            ec2.wait_for_status_change(['i-aabbccdd'], conn, filters={})

    def test_ec2_wait_for_status_change_stopped_not_found(self):
        """
        When waiting for the 'stopped' state, if an instance is not found
        it is considered to be an error and the method will throw
        an InstanceIDNotFound exception.
        """
        filters = {'instance-state-name': 'stopped',
                   'key-name': self.full_params['keyname']}
        ec2 = self.factory.create_agent('ec2')
        conn = ec2.open_connection(self.full_params)
        # Throw an invalid id when stopping an instance. wait_for_status should raise an
        # exception.
        (self.fake_ec2.should_receive('get_all_reservations')
         .and_raise(EC2ResponseError(400, "no reason",
                                     self.instance_notfound_body.format('i-aabbccdd'))))

        with self.assertRaises(InstanceIDNotFound):
            ec2.wait_for_status_change(['i-aabbccdd'], conn, filters, 5, 1)

    def test_ec2_wait_for_status_change_already_terminated(self):
        """
        Terminate an instance and the cloud returns InvalidInstanceID.NotFound

        This should be reported as a success
        """
        filters = {'instance-state-name': 'terminated',
                   'key-name': self.full_params['keyname']}
        ec2 = self.factory.create_agent('ec2')
        conn = ec2.open_connection(self.full_params)

        instance_ids = ['i-aabbccdd']
        self.fake_ec2.should_receive('get_all_reservations').and_raise(
            EC2ResponseError(400, "no reason", self.instance_notfound_body.format(instance_ids[0])))

        result = ec2.wait_for_status_change(instance_ids, conn, filters, max_wait_time=10, poll_interval=1)
        self.assertTrue(result)

    def test_ec2_wait_for_status_change_one_not_found_terminated(self):
        """
        The first instance id in the list is marked as not found.

        Note: self.terminated_reservations does return the instance id, which shouldn't have an impact
        """
        filters = {'instance-state-name': 'terminated',
                   'key-name': self.full_params['keyname']}
        ec2 = self.factory.create_agent('ec2')
        conn = ec2.open_connection(self.full_params)

        instance_ids = ['i-aabbccdd', 'i-aabbccee', 'i-aabbccff']
        (self.fake_ec2.should_receive('get_all_reservations')
            .and_raise(EC2ResponseError(400, "no reason",
                                        self.instance_notfound_body.format(instance_ids[0])))
            .and_return(self.terminated_reservations))

        result = ec2.wait_for_status_change(instance_ids, conn, filters, max_wait_time=10, poll_interval=1)

        self.assertTrue(result)

    def test_ec2_wait_for_status_change_all_not_found_terminated(self):
        """
        Case where all instances are not found

        Should return True
        """
        filters = {'instance-state-name': 'terminated',
                   'key-name': self.full_params['keyname']}
        ec2 = self.factory.create_agent('ec2')
        conn = ec2.open_connection(self.full_params)
        instance_ids = ['i-aabbccdd', 'i-aabbccee', 'i-aabbccff']

        # Raise an exception for each instance id in serial
        (self.fake_ec2.should_receive('get_all_reservations')
         .and_raise(EC2ResponseError(400, "no reason", self.instance_notfound_body.format(instance_ids[0])))
         .and_raise(EC2ResponseError(400, "no reason", self.instance_notfound_body.format(instance_ids[1])))
         .and_raise(EC2ResponseError(400, "no reason", self.instance_notfound_body.format(instance_ids[2]))))

        result = ec2.wait_for_status_change(instance_ids, conn, filters, max_wait_time=5, poll_interval=1)

        self.assertTrue(result)

    def test_ec2_wait_for_status_change_multiple_not_found(self):
        """
        Case where multiple instances are not found.

        Should return True
        """
        filters = {'instance-state-name': 'terminated',
                   'key-name': self.full_params['keyname']}
        ec2 = self.factory.create_agent('ec2')
        conn = ec2.open_connection(self.full_params)
        instance_ids = ['i-aabbccdd', 'i-aabbccee', 'i-aabbccff']

        # Raise exception for the first two instance ids.
        missing_ids = ','.join(instance_ids[0:2])
        (self.fake_ec2.should_receive('get_all_reservations')
         .and_raise(EC2ResponseError(400, "no reason",
                                     self.multiple_instances_not_found.format(missing_ids)))
         .and_return(self.terminated_reservations))

        result = ec2.wait_for_status_change(instance_ids, conn, filters, max_wait_time=5, poll_interval=1)

        self.assertTrue(result)

    def test_ec2_wait_for_status_change_multiple_not_found_different_order(self):
        """
        Multiple instance ids not found, first one is found

        Should return True
        """
        filters = {'instance-state-name': 'terminated',
                   'key-name': self.full_params['keyname']}
        ec2 = self.factory.create_agent('ec2')
        conn = ec2.open_connection(self.full_params)
        instance_ids = ['i-aabbccdd', 'i-aabbccee', 'i-aabbccff']

        # Raise exception for the first two instance ids.
        missing_ids = ','.join(instance_ids[1:])
        (self.fake_ec2.should_receive('get_all_reservations')
         .and_raise(EC2ResponseError(400, "no reason",
                                     self.multiple_instances_not_found.format(missing_ids)))
         .and_return(self.terminated_reservations))

        result = ec2.wait_for_status_change(instance_ids, conn, filters, max_wait_time=5, poll_interval=1)

        self.assertTrue(result)

    def test_ec2_wait_for_status_change_keeps_on_running(self):
        """
        Case where all instances keep running and never reach 'terminated'

        Should return False
        """
        filters = {'instance-state-name': 'terminated',
                   'key-name': self.full_params['keyname']}
        ec2 = self.factory.create_agent('ec2')
        conn = ec2.open_connection(self.full_params)
        # First element is missing
        instance_ids = ['i-aabbccdd', 'i-aabbccee', 'i-aabbccff']

        (self.fake_ec2.should_receive('get_all_reservations')
            .and_raise(EC2ResponseError(400, 'no reason',
                                        self.instance_notfound_body.format(instance_ids[1])))
            .and_return(self.empty_reservations)
            .and_return(self.empty_reservations)
            .and_return(self.empty_reservations)
            .and_return(self.empty_reservations)
         )

        # Last two won't reach terminated state
        result = ec2.wait_for_status_change(instance_ids, conn, filters, max_wait_time=3, poll_interval=1)

        self.assertFalse(result)

    def test_ec2_wait_for_status_change_successfully_terminated(self):
        """
        The first instance id in the list is marked as not found.

        Note: self.terminated_reservations does return the instance id, which shouldn't have an impact
        """
        filters = {'instance-state-name': 'terminated',
                   'key-name': self.full_params['keyname']}
        ec2 = self.factory.create_agent('ec2')
        conn = ec2.open_connection(self.full_params)

        instance_ids = ['i-aabbccdd', 'i-aabbccee', 'i-aabbccff']
        (self.fake_ec2.should_receive('get_all_reservations')
            .and_return(self.terminated_reservations))

        result = ec2.wait_for_status_change(instance_ids, conn, filters, max_wait_time=10, poll_interval=1)

        self.assertTrue(result)

    def tearDown(self):
        pass


class TestEC2AgentTerminateInstances(TestCase):
    def setUp(self):
        self.factory = InfrastructureAgentFactory()
        self.fake_ec2 = flexmock(name='self.fake_ec2')
        flexmock(boto.ec2)
        boto.ec2.should_receive('connect_to_region').and_return(self.fake_ec2)

        reservation = Reservation()
        instance = flexmock(name='instance', private_dns_name='private-ip',
                            public_dns_name='public-ip', id='i-aabbccee', state='running',
                            key_name='bookeyname', ip_address='public-ip',
                            private_ip_address='private-ip')
        new_instance = flexmock(name='new-instance', private_dns_name='new-private-ip',
                                public_dns_name='new-public-ip', id='i-aabbccff',
                                state='running', key_name='bookeyname',
                                ip_address='new-public-ip',
                                private_ip_address='new-private-ip')

        t_aabbccee = flexmock(name='instance', private_dns_name='private-ip',
                            public_dns_name='public-ip', id='i-aabbccee', state='terminated',
                            key_name='bookeyname', ip_address='public-ip',
                            private_ip_address='private-ip')
        t_aabbccff = flexmock(name='new-instance', private_dns_name='new-private-ip',
                                public_dns_name='new-public-ip', id='i-aabbccff',
                                state='terminated', key_name='bookeyname',
                                ip_address='new-public-ip',
                                private_ip_address='new-private-ip')
        t_aabbccdd = flexmock(name='instance', private_dns_name='private-ip',
                              public_dns_name='public-ip', id='i-aabbccdd', state='terminated',
                              key_name='bookeyname', ip_address='public-ip',
                              private_ip_address='private-ip')

        reservation.instances = [instance]
        new_reservation = Reservation()
        new_reservation.instances = [instance, new_instance]

        # For testing wait_for_status
        self.good_reservation = Reservation()
        self.good_reservation.instances = [instance, new_instance]
        self.good_reservations = [self.good_reservation]
        self.terminated_reservation = Reservation()

        # Used because we filter for 'terminated' and it should return no instances..
        self.empty_reservation = Reservation()
        self.empty_reservation.instances = []
        self.empty_reservations = [self.empty_reservation]

        self.terminated_reservation.instances = [t_aabbccee, t_aabbccff, t_aabbccdd]
        self.terminated_reservations = [self.terminated_reservation]

        self.instance_notfound_body = """
        <Response xmlns=""><Errors>
        <Error>
        <Code>InvalidInstanceID.NotFound</Code>
        <Message>The instance ID '{}' does not exist</Message>
        </Error></Errors>
        <RequestID>23548a3a-d6c8-4de7-b846-4e072587c582</RequestID></Response>
        """

        self.multiple_instance_notfound_body = """
        <Response xmlns=""><Errors>
        <Error>
        <Code>InvalidInstanceID.NotFound</Code>
        <Message>The instance IDs '{}' do not exist</Message>
        </Error></Errors>
        <RequestID>23548a3a-d6c8-4de7-b846-4e072587c582</RequestID></Response>
        """

        self.full_params = {
            'credentials': {
                'a': 'b', 'EC2_URL': 'http://testing.appscale.com:8773/foo/bar',
                'EC2_ACCESS_KEY': 'access_key', 'EC2_SECRET_KEY': 'secret_key'},
            'group': 'boogroup',
            'image_id': 'booid',
            'infrastructure': 'ec2',
            'instance_type': 'booinstance_type',
            'keyname': 'bookeyname',
            'num_vms': '1',
            'use_spot_instances': False,
            'region': 'my-zone-1',
            'zone': 'my-zone-1b',
            'autoscale_agent': True,
        }

    def test_ec2_terminate_instances(self):
        """
        Test out a successful terminate instances
        """
        # Uncomment to get logging from the agent, helpful for debugging
        #logging.basicConfig(level=logging.DEBUG)
        #l = logging.getLogger('appscale.agents.ec_agent')
        #l.setLevel(logging.DEBUG)

        ec2 = self.factory.create_agent('ec2')

        (self.fake_ec2.should_receive('terminate_instances')
         .and_return(True))

        self.full_params['instance_ids'] = ['i-aabbccdd', 'i-aabbccee', 'i-aabbccff']

        (self.fake_ec2.should_receive('get_all_reservations')
            .and_return(self.terminated_reservations))

        instance_ids = set(self.full_params[ec2.PARAM_INSTANCE_IDS])
        status_filters = {"instance-state-name": 'terminated',
                          "key-name": self.full_params[ec2.PARAM_KEYNAME]}
        conn = ec2.open_connection(self.full_params)
        result = ec2._EC2Agent__terminate_instances(instance_ids, conn, status_filters, max_attempts=1)
        self.assertTrue(result)

    def test_ec2_terminate_instances_invalid_id(self):
        """
        Test out an invalid instance id
        """
        ec2 = self.factory.create_agent('ec2')
        instance_ids = ['i-aabbccdd', 'i-aabbccee', 'i-aabbccff']
        self.full_params['instance_ids'] = instance_ids

        # First instance ID doesn't exist, second call will succeed
        (self.fake_ec2.should_receive('terminate_instances')
         .and_raise(EC2ResponseError(400, 'no reason',
                                     self.instance_notfound_body.format(instance_ids[0])))
         .and_return(True))

        # _wait_for_status should return true.
        (self.fake_ec2.should_receive('get_all_reservations')
         .and_return(self.terminated_reservations))

        instance_ids = set(self.full_params[ec2.PARAM_INSTANCE_IDS])
        status_filters = {"instance-state-name": 'terminated',
                          "key-name": self.full_params[ec2.PARAM_KEYNAME]}
        conn = ec2.open_connection(self.full_params)
        result = ec2._EC2Agent__terminate_instances(instance_ids, conn, status_filters, max_attempts=1)
        self.assertTrue(result)

    def test_ec2_terminate_instances_multiple_invalid_id(self):
        """
        Test out a multiple invalid instance ids.
        """
        # Uncomment to get logging from the agent, helpful for debugging
        logging.basicConfig(level=logging.DEBUG)
        l = logging.getLogger('appscale.agents.ec_agent')
        l.setLevel(logging.DEBUG)

        ec2 = self.factory.create_agent('ec2')
        instance_ids = ['i-aabbccdd', 'i-aabbccee', 'i-aabbccff']
        self.full_params['instance_ids'] = instance_ids

        # First instance ID doesn't exist, second call will succeed
        (self.fake_ec2.should_receive('terminate_instances')
         .and_raise(EC2ResponseError(400, 'no reason',
                                     self.multiple_instance_notfound_body.format(instance_ids[0:2])))
         .and_return(True))

        # _wait_for_status should return true.
        (self.fake_ec2.should_receive('get_all_reservations')
         .and_return(self.terminated_reservations))

        instance_ids = set(self.full_params[ec2.PARAM_INSTANCE_IDS])
        status_filters = {"instance-state-name": 'terminated',
                          "key-name": self.full_params[ec2.PARAM_KEYNAME]}
        conn = ec2.open_connection(self.full_params)
        result = ec2._EC2Agent__terminate_instances(instance_ids, conn, status_filters, max_attempts=1)
        self.assertTrue(result)

    def test_ec2_terminate_instances_all_not_found(self):
        """
        Test out all not found, should return true
        """
        # Uncomment to get logging from the agent, helpful for debugging
        logging.basicConfig(level=logging.DEBUG)
        l = logging.getLogger('appscale.agents.ec_agent')
        l.setLevel(logging.DEBUG)

        ec2 = self.factory.create_agent('ec2')
        instance_ids = ['i-aabbccdd', 'i-aabbccee', 'i-aabbccff']
        self.full_params['instance_ids'] = instance_ids

        # First instance ID doesn't exist, second call will succeed
        (self.fake_ec2.should_receive('terminate_instances')
         .and_raise(EC2ResponseError(400, 'no reason',
                                     self.multiple_instance_notfound_body.format(instance_ids[:])))
         .and_return(True))

        # _wait_for_status should return true.
        (self.fake_ec2.should_receive('get_all_reservations')
         .and_return(self.terminated_reservations))

        instance_ids = set(self.full_params[ec2.PARAM_INSTANCE_IDS])
        status_filters = {"instance-state-name": 'terminated',
                          "key-name": self.full_params[ec2.PARAM_KEYNAME]}
        conn = ec2.open_connection(self.full_params)
        result = ec2._EC2Agent__terminate_instances(instance_ids, conn, status_filters, max_attempts=1)

        self.assertTrue(result)

    def test_ec2_terminate_instances_keeps_running(self):
        """
        Test out case where all instances keep running.
        boto.terminate_instances throws InstanceIDInvalid.NotFound
        We recover and keep waiting for the other 2 instances, which keep running
        and do *not* terminate.

        Will take about 120 seconds to run (timeout)

        Should return False
        """
        ec2 = self.factory.create_agent('ec2')
        instance_ids = ['i-aabbccdd', 'i-aabbccee', 'i-aabbccff']
        self.full_params['instance_ids'] = instance_ids

        # First instance ID doesn't exist, second call will succeed
        (self.fake_ec2.should_receive('terminate_instances')
         .and_raise(EC2ResponseError(400, 'no reason',
                                     self.instance_notfound_body.format(instance_ids[0])))
         .and_return(True))

        # _wait_for_status should return true.
        (self.fake_ec2.should_receive('get_all_reservations')
         .and_return(self.empty_reservations))

        instance_ids = set(self.full_params[ec2.PARAM_INSTANCE_IDS])
        status_filters = {"instance-state-name": 'terminated',
                          "key-name": self.full_params[ec2.PARAM_KEYNAME]}
        conn = ec2.open_connection(self.full_params)
        result = ec2._EC2Agent__terminate_instances(instance_ids, conn, status_filters, max_attempts=1)

        self.assertFalse(result)


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

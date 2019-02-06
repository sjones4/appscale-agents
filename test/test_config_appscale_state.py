import os
import sys
import stat
import time
import tempfile
import subprocess

from appscale.agents.config import AppScaleState
from appscale.agents.agent_exceptions import ShellException

from unittest import TestCase

from flexmock import flexmock


class TestAppScaleState(TestCase):
    def setUp(self):
        self.user_dir = os.path.expanduser('~')
        self.appscale_dir = '.appscale'
        self.default_configdir = os.path.join(self.user_dir, self.appscale_dir)
        self.default_keyname = 'UNITTESTKEY'
        self.default_locations_content = """
        {
        "infrastructure_info": {
            "group": "sgrahamappgroup",
            "infrastructure": "gce",
            "project": "appscale-staging",
            "zone": "us-central1-a",
            "azure_storage_account":"UNIT_TEST_STORAGE",
            "azure_resource_group":"UNIT_TEST_RESOURCE",
            "azure_tenant_id":"UNIT_TEST_TENANT_ID",
            "azure_app_secret_key":"SSSSHITSASECRET",
            "azure_app_id":"UNIT_TEST_APPID",
            "azure_subscription_id":"UNIT_TEST_SUBSCRIPTION_ID",
        },
        "node_info": [
        {
            "cloud": "cloud1",
            "disk": null,
            "instance_id": "dummyappgroup-9c3dc2be-a1ca-4dca-a32a-3dd58c407031",
            "instance_type": "n1-standard-1",
            "jobs": [
                "load_balancer",
                "compute",
                "database",
                "zookeeper",
                "taskqueue_master",
                "db_master",
                "taskqueue",
                "memcache",
                "shadow",
                "login"
            ],
            "private_ip": "10.240.0.2",
            "public_ip": "172.16.10.10",
            "ssh_key": "/etc/appscale/keys/cloud1/appscale3cc1f78769994c6ab909d278ff18d0e3.key"
        }
    ]
}
        """
        self.old_config_json = """
        {
        "node_info": [
        {
            "cloud": "cloud1",
            "disk": null,
            "instance_id": "dummyappgroup-9c3dc2be-a1ca-4dca-a32a-3dd58c407031",
            "instance_type": "n1-standard-1",
            "jobs": [
                "load_balancer",
                "compute",
                "database",
                "zookeeper",
                "taskqueue_master",
                "db_master",
                "taskqueue",
                "memcache",
                "shadow",
                "login"
            ],
            "private_ip": "10.240.0.2",
            "public_ip": "172.16.10.11",
            "ssh_key": "/etc/appscale/keys/cloud1/appscale3cc1f78769994c6ab909d278ff18d0e3.key"
        }
    ]
}
        """
        self.old_config_yaml = """
        {
        "infrastructure_info": {
            "group": "sgrahamappgroup",
            "infrastructure": "gce",
            "project": "appscale-staging",
            "zone": "us-central1-a",
            "azure_storage_account":"UNIT_TEST_STORAGE",
            "azure_resource_group":"UNIT_TEST_RESOURCE",
            "azure_tenant_id":"UNIT_TEST_TENANT_ID",
            "azure_app_secret_key":"SSSSHITSASECRET",
            "azure_app_id":"UNIT_TEST_APPID",
            "azure_subscription_id":"UNIT_TEST_SUBSCRIPTION_ID",
            }
        }
        """

    def test_config_path(self):
        actual = AppScaleState.config_path()
        expected = self.default_configdir
        self.assertEqual(expected, actual)

    def test_private_key(self):
        actual = AppScaleState.private_key(self.default_keyname)
        expected = os.path.join(self.default_configdir, self.default_keyname)
        self.assertEqual(expected, actual)

    def test_public_key(self):
        actual = AppScaleState.public_key(self.default_keyname)
        expected = os.path.join(self.user_dir, self.appscale_dir, "{0}.pub".format(self.default_keyname))
        self.assertEqual(expected, actual)

    def test_ssh_key(self):
        actual = AppScaleState.ssh_key(self.default_keyname)
        expected = os.path.join(self.default_configdir, "{0}.key".format(self.default_keyname))
        self.assertEqual(expected, actual)

    def test_write_key_file(self):

        # Write the test key into the /tmp directory for unit testing
        filename = '/tmp/unit_test_key.key'
        contents = "TEST CONTENT"
        AppScaleState.write_key_file(filename, contents)
        actual_contents = open(filename).read()
        s = os.stat(filename)

        # expected octal 0600
        expected_mode = stat.S_IWUSR | stat.S_IRUSR

        # we are only interested in the user/group/other bits
        perm_bits = (stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
        mode = s.st_mode & perm_bits

        # If the xor is 0, then the permissions are as expected
        # otherwise the permission bits are off.
        self.assertEqual(0, mode ^ expected_mode)
        os.remove(filename)

        # assert if the contents aren't the same.
        self.assertEqual(contents, actual_contents)

    def test_get_client_secrets_location(self):
        location = AppScaleState.get_client_secrets_location(self.default_keyname)
        expected = os.path.join(AppScaleState.config_path(),
                                "{0}-secrets.json".format(self.default_keyname))
        self.assertEqual(expected, location)

    def test_get_oauth2_storage_location(self):
        location = AppScaleState.get_oauth2_storage_location(self.default_keyname)
        expected = os.path.join(AppScaleState.config_path(),
                                "{0}-oauth2.dat".format(self.default_keyname))
        self.assertEqual(expected, location)

    def test_locations_json_location(self):
        location = AppScaleState.locations_json_location(self.default_keyname)
        expected = os.path.join(AppScaleState.config_path(),
                                "locations-{0}.json".format(self.default_keyname))
        self.assertEqual(expected, location)

    def test_locations_yaml_location(self):
        location = AppScaleState.locations_yaml_location(self.default_keyname)
        expected = os.path.join(AppScaleState.config_path(),
                                "locations-{0}.yaml".format(self.default_keyname))
        self.assertEqual(expected, location)

    def test_generate_rsa_key(self):
        AppScaleState.generate_rsa_key(self.default_keyname, False)
        dest_file = os.path.join(self.default_configdir, self.default_keyname)
        self.assertTrue(os.path.exists(dest_file),
                        "dest file doesn't exist: {0}".format(dest_file))
        self.assertTrue(os.path.exists(dest_file + '.key'),
                        "dest_file doesn't exist: {0}".format(dest_file + '.key'))

    def test_get_group(self):
        builtins = flexmock(sys.modules['__builtin__'])
        fake_locations_json = flexmock(name='fake_locations_json')
        fake_locations_json.should_receive('read').and_return(self.default_locations_content)

        builtins.should_call('open')
        (builtins.should_receive('open')
            .with_args(AppScaleState.locations_json_location(self.default_keyname), 'r')
            .and_return(fake_locations_json))

        group = AppScaleState.get_group(self.default_keyname)
        expected = 'sgrahamappgroup'
        self.assertEqual(expected, group)

    def test_get_project(self):
        builtins = flexmock(sys.modules['__builtin__'])
        fake_locations_json = flexmock(name='fake_locations_json')
        fake_locations_json.should_receive('read').and_return(self.default_locations_content)

        builtins.should_call('open')
        (builtins.should_receive('open')
            .with_args(AppScaleState.locations_json_location(self.default_keyname), 'r')
            .and_return(fake_locations_json))

        actual = AppScaleState.get_project(self.default_keyname)
        expected = 'appscale-staging'
        self.assertEqual(expected, actual)

    def test_get_zone(self):
        builtins = flexmock(sys.modules['__builtin__'])
        fake_locations_json = flexmock(name='fake_locations_json')
        fake_locations_json.should_receive('read').and_return(self.default_locations_content)

        builtins.should_call('open')
        (builtins.should_receive('open')
            .with_args(AppScaleState.locations_json_location(self.default_keyname), 'r')
            .and_return(fake_locations_json))

        actual = AppScaleState.get_zone(self.default_keyname)
        expected = 'us-central1-a'
        self.assertEqual(expected, actual)

    def test_get_subscription_id(self):
        builtins = flexmock(sys.modules['__builtin__'])
        fake_locations_json = flexmock(name='fake_locations_json')
        fake_locations_json.should_receive('read').and_return(self.default_locations_content)

        builtins.should_call('open')
        (builtins.should_receive('open')
            .with_args(AppScaleState.locations_json_location(self.default_keyname), 'r')
            .and_return(fake_locations_json))

        actual = AppScaleState.get_subscription_id(self.default_keyname)
        expected = 'UNIT_TEST_SUBSCRIPTION_ID'
        self.assertEqual(expected, actual)

    def test_get_app_id(self):
        builtins = flexmock(sys.modules['__builtin__'])
        fake_locations_json = flexmock(name='fake_locations_json')
        fake_locations_json.should_receive('read').and_return(self.default_locations_content)

        builtins.should_call('open')
        (builtins.should_receive('open')
            .with_args(AppScaleState.locations_json_location(self.default_keyname), 'r')
            .and_return(fake_locations_json))

        actual = AppScaleState.get_project(self.default_keyname)
        expected = 'appscale-staging'
        self.assertEqual(expected, actual)

    def test_get_app_secret_key(self):
        builtins = flexmock(sys.modules['__builtin__'])
        fake_locations_json = flexmock(name='fake_locations_json')
        fake_locations_json.should_receive('read').and_return(self.default_locations_content)

        builtins.should_call('open')
        (builtins.should_receive('open')
            .with_args(AppScaleState.locations_json_location(self.default_keyname), 'r')
            .and_return(fake_locations_json))

        actual = AppScaleState.get_project(self.default_keyname)
        expected = 'appscale-staging'
        self.assertEqual(expected, actual)

    def test_get_tenant_id(self):
        builtins = flexmock(sys.modules['__builtin__'])
        fake_locations_json = flexmock(name='fake_locations_json')
        fake_locations_json.should_receive('read').and_return(self.default_locations_content)

        builtins.should_call('open')
        (builtins.should_receive('open')
            .with_args(AppScaleState.locations_json_location(self.default_keyname), 'r')
            .and_return(fake_locations_json))

        actual = AppScaleState.get_project(self.default_keyname)
        expected = 'appscale-staging'
        self.assertEqual(expected, actual)

    def test_get_resource_group(self):
        builtins = flexmock(sys.modules['__builtin__'])
        fake_locations_json = flexmock(name='fake_locations_json')
        fake_locations_json.should_receive('read').and_return(self.default_locations_content)

        builtins.should_call('open')
        (builtins.should_receive('open')
            .with_args(AppScaleState.locations_json_location(self.default_keyname), 'r')
            .and_return(fake_locations_json))

        actual = AppScaleState.get_project(self.default_keyname)
        expected = 'appscale-staging'
        self.assertEqual(expected, actual)

    def test_get_storage_account(self):
        builtins = flexmock(sys.modules['__builtin__'])
        fake_locations_json = flexmock(name='fake_locations_json')
        fake_locations_json.should_receive('read').and_return(self.default_locations_content)

        builtins.should_call('open')
        (builtins.should_receive('open')
            .with_args(AppScaleState.locations_json_location(self.default_keyname), 'r')
            .and_return(fake_locations_json))

        actual = AppScaleState.get_storage_account(self.default_keyname)
        expected = 'UNIT_TEST_STORAGE'
        self.assertEqual(expected, actual)

    def test_get_infrastructure_option(self):
        builtins = flexmock(sys.modules['__builtin__'])
        fake_locations_json = flexmock(name='fake_locations_json')
        fake_locations_json.should_receive('read').and_return(self.default_locations_content)

        builtins.should_call('open')
        (builtins.should_receive('open')
            .with_args(AppScaleState.locations_json_location(self.default_keyname), 'r')
            .and_return(fake_locations_json))

        actual = AppScaleState.get_infrastructure_option('project', self.default_keyname)
        expected = 'appscale-staging'
        self.assertEqual(expected, actual)

    def test_upgrade_json_file(self):
        json_loc = AppScaleState.locations_json_location(self.default_keyname)
        yaml_loc = AppScaleState.locations_yaml_location(self.default_keyname)

        with open(json_loc, 'wc') as json_fh:
            json_fh.write(self.old_config_json)

        with open(yaml_loc, 'wc') as yaml_fh:
            yaml_fh.write(self.old_config_yaml)

        AppScaleState.upgrade_json_file(self.default_keyname)

        # JSON content should be the
        expected = """{"node_info": {"node_info": [{"public_ip": "172.16.10.11", "jobs": ["load_balancer", "compute", "database", "zookeeper", "taskqueue_master", "db_master", "taskqueue", "memcache", "shadow", "login"], "ssh_key": "/etc/appscale/keys/cloud1/appscale3cc1f78769994c6ab909d278ff18d0e3.key", "instance_id": "dummyappgroup-9c3dc2be-a1ca-4dca-a32a-3dd58c407031", "instance_type": "n1-standard-1", "private_ip": "10.240.0.2", "disk": null, "cloud": "cloud1"}]}, "infrastructure_info": {"infrastructure_info": {"azure_app_secret_key": "SSSSHITSASECRET", "infrastructure": "gce", "group": "sgrahamappgroup", "zone": "us-central1-a", "project": "appscale-staging", "azure_resource_group": "UNIT_TEST_RESOURCE", "azure_tenant_id": "UNIT_TEST_TENANT_ID", "azure_subscription_id": "UNIT_TEST_SUBSCRIPTION_ID", "azure_storage_account": "UNIT_TEST_STORAGE", "azure_app_id": "UNIT_TEST_APPID"}}}"""
        actual = "DIDNTREAD"
        with open(json_loc, 'r') as json_fh:
            actual = json_fh.read()
        self.assertEqual(expected, actual)
        # yaml file should now be gone
        self.assertFalse(os.path.exists(yaml_loc))

    def test_shell_exceptions(self):
        fake_tmp_file = flexmock(name='tempfile')
        fake_tmp_file.should_receive('write').and_return()
        fake_tmp_file.should_receive('read').and_return('')
        fake_tmp_file.should_receive('seek').and_return()
        fake_tmp_file.should_receive('close').and_return()
        (flexmock(tempfile).should_receive('NamedTemporaryFile')
        .and_return(fake_tmp_file))
        (flexmock(tempfile).should_receive('TemporaryFile')
        .and_return(fake_tmp_file))

        fake_result = flexmock(name='result')
        fake_result.returncode = 1
        fake_result.should_receive('wait').and_return()
        fake_subprocess = flexmock(subprocess)
        fake_subprocess.should_receive('Popen').and_return(fake_result)
        fake_subprocess.STDOUT = ''
        flexmock(time).should_receive('sleep').and_return()

        self.assertRaises(ShellException, AppScaleState.shell, 'fake_cmd', False)
        self.assertRaises(ShellException, AppScaleState.shell, 'fake_cmd', False,
                          stdin='fake_stdin')

        fake_subprocess.should_receive('Popen').and_raise(OSError)

        self.assertRaises(ShellException, AppScaleState.shell, 'fake_cmd', False)
        self.assertRaises(ShellException, AppScaleState.shell, 'fake_cmd', False,
                          stdin='fake_stdin')

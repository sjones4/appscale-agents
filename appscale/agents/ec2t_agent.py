"""
Helper library for EC2 interaction using a launch template
"""
import boto3
import datetime
import glob
import logging
import uuid

from botocore.exceptions import BotoCoreError, ClientError
from boto3.exceptions import Boto3Error

from appscale.agents.config import AppScaleState
from appscale.agents.base_agent import AgentConfigurationException
from appscale.agents.base_agent import AgentRuntimeException
from appscale.agents.base_agent import BaseAgent


logger = logging.getLogger(__name__)

class EC2TemplateAgent(BaseAgent):
  """
  EC2 infrastructure agent class which can be used to spawn and terminate
  VMs in an EC2 based environment.
  """

  PARAM_CLIENT_TOKEN = 'aws_client_token'
  PARAM_LAUNCH_TEMPLATE_ID = 'aws_launch_template_id'

  REQUIRED_EC2_RUN_INSTANCES_PARAMS = (
    PARAM_LAUNCH_TEMPLATE_ID,
  )

  REQUIRED_EC2_TERMINATE_INSTANCES_PARAMS = (
    BaseAgent.PARAM_INSTANCE_IDS,
  )

  def get_flags(self):
    """Get the feature flags for this agent"""
    return (self.FLAG_DISK_AUTO, self.FLAG_INSTANCE_TYPE_AUTO,
            self.FLAG_KEY_AUTO, self.FLAG_SSH_AUTO)


  def assert_credentials_are_valid(self, parameters):
    """Contacts AWS to see if the given access key and secret key represent a
    valid set of credentials.

    Args:
      parameters: A dict containing the user's AWS access key and secret key.
    Raises:
      AgentConfigurationException: If the given AWS access key and secret key
      cannot be used to make requests to AWS.
    """
    ec2 = self.ec2_client(parameters)
    try:
      ec2.describe_instances()
    except Boto3Error:
      raise AgentConfigurationException("We couldn't describe " + \
        "instances. Are your credentials valid?")

  def configure_instance_security(self, parameters):
    """
    The user of this agent is expected to provide appropriate security for
    instances via the launch template.

    Args:
      parameters: A dictionary of parameters.
    """
    return False

  def get_params_from_args(self, args):
    """
    Searches through args to build a dict containing the parameters
    necessary to interact with Amazon EC2.

    Args:
      args: A Namespace containing the arguments that the user has
        invoked an AppScale Tool with.
    """
    # need to convert this to a dict if it is not already
    if not isinstance(args, dict):
      args = vars(args)

    params = {
      self.PARAM_VERBOSE : args.get('verbose', False),
      self.PARAM_AUTOSCALE_AGENT : False
    }

    launch_template_id = args.get(self.PARAM_LAUNCH_TEMPLATE_ID)
    if not launch_template_id:
      raise AgentConfigurationException('Launch template identifier required.')
    params[self.PARAM_LAUNCH_TEMPLATE_ID] = launch_template_id

    self.assert_credentials_are_valid(params)

    return params

  def get_cloud_params(self, keyname):
    """Searches through the locations.json file with key
    'infrastructure_info' to build a dict containing the
    parameters necessary to interact with Amazon EC2.

    Args:
      keyname: The name of the SSH keypair that uniquely identifies this
        AppScale deployment.
    """
    launch_template_id = AppScaleState.get_infrastructure_option(
        tag=self.PARAM_LAUNCH_TEMPLATE_ID, keyname=keyname)

    if not launch_template_id:
      raise AgentConfigurationException('Launch template identifier required.')

    return {self.PARAM_LAUNCH_TEMPLATE_ID : launch_template_id}

  def assert_required_parameters(self, parameters, operation):
    """
    Assert that all the parameters required for the EC2 agent are in place.
    (Also see documentation for the BaseAgent class)

    Args:
      parameters: A dictionary of parameters.
      operation: Operations to be invoked using the above parameters.
    """
    required_params = ()
    if operation == BaseAgent.OPERATION_RUN:
      required_params = self.REQUIRED_EC2_RUN_INSTANCES_PARAMS
    elif operation == BaseAgent.OPERATION_TERMINATE:
      required_params = self.REQUIRED_EC2_TERMINATE_INSTANCES_PARAMS

    # make sure the user set something for each parameter
    for param in required_params:
      if not self.has_parameter(param, parameters):
        raise AgentConfigurationException('no ' + param)

  def describe_instances(self, parameters, pending=False):
    """
    Retrieves the list of running instances that have been instantiated by
    this agent.

    Args:
      parameters: A dictionary containing a 'aws_launch_template_id'
        parameter.
      pending: Indicates we also want the pending instances.
    Returns:
      A tuple of the form (public_ips, private_ips, instances) where each
      member is a list.
    """
    client_token = parameters.get(self.PARAM_CLIENT_TOKEN)
    launch_template_id = parameters.get(self.PARAM_LAUNCH_TEMPLATE_ID)

    states = ['running']
    if pending:
      states.append('pending')

    ec2 = self.ec2_client(parameters)
    filters = [
      {
        'Name': 'instance-state-name',
        'Values': states
      },
    ]
    if client_token:
      filters.append({
        'Name': 'client-token',
        'Values': [client_token]
      })
    if launch_template_id:
      filters.append({
        'Name': 'tag:aws:ec2launchtemplate:id',
        'Values': [launch_template_id]
      })
    describe_response = ec2.describe_instances(Filters=filters)
    reservations = describe_response.get('Reservations', [])
    instances = [i for r in reservations for i in r.get('Instances', [])]
    instance_ids = []
    public_ips = []
    private_ips = []
    for i in instances:
      instance_ids.append(i['InstanceId'])
      public_ips.append(i.get('PublicIpAddress') or i['PrivateIpAddress'])
      private_ips.append(i['PrivateIpAddress'])
    return public_ips, private_ips, instance_ids

  def run_instances(self, count, parameters, security_configured, public_ip_needed):
    """
    Spawns the specified number of EC2 instances using the parameters
    provided. This method is blocking in that it waits until the
    requested VMs are properly booted up. However if the requested
    VMs cannot be procured within 1800 seconds, this method will treat
    it as an error and return. (Also see documentation for the BaseAgent
    class)

    Args:
      count: Number of VMs to spawned.
      parameters: A dictionary of parameters. This must contain
        a 'aws_launch_template_id' parameter.
      security_configured: Uses this boolean value as an heuristic to
        detect brand new AppScale deployments.
      public_ip_needed: Ignored, this agent expected addressing to be
        externally configured.
    Returns:
      A tuple of the form (instances, public_ips, private_ips)
    """
    launch_template_id = parameters[self.PARAM_LAUNCH_TEMPLATE_ID]

    logger.info("Starting {0} machines with template id {1}"
                .format(count, launch_template_id))

    try:
      start_time = datetime.datetime.now()
      ec2 = self.ec2_client(parameters)

      client_token = launch_template_id + '-' + str(uuid.uuid4())

      ec2.run_instances(MinCount=count,
                        MaxCount=count,
                        LaunchTemplate={
                            'LaunchTemplateId': launch_template_id
                        },
                        ClientToken=client_token)

      ec2_waiter = ec2.get_waiter('instance_running')
      ec2_waiter.wait(Filters=[{
          'Name': 'client-token',
          'Values': [client_token]
      }])

      describe_parameters = dict(parameters)
      describe_parameters[self.PARAM_CLIENT_TOKEN] = client_token
      public_ips, private_ips, instance_ids = self.describe_instances(
          describe_parameters)

      end_time = datetime.datetime.now()
      total_time = end_time - start_time
      logger.info("Started {0} instances in {1} seconds"
                  .format(count, total_time.seconds))
      return instance_ids, public_ips, private_ips
    except (Boto3Error, BotoCoreError) as exception:
      self.handle_failure('EC2 response error while starting instance(s): ' +
                          exception.message)

  def associate_static_ip(self, parameters, instance_id, elastic_ip):
    """Does nothing.

    Args:
      parameters: A dict that includes the credentials necessary to communicate
        with Amazon Web Services.
      instance_id: A str naming the running instance to associate an Elastic IP
        with.
      elastic_ip: A str naming the already allocated Elastic IP address that
        will be associated.
    """
    pass

  def terminate_instances(self, parameters):
    """
    Terminate one of more EC2 instances. The input instance IDs are
    fetched from the 'instance_ids' parameters in the input map. (Also
    see documentation for the BaseAgent class)

    Args:
      parameters: A dictionary of parameters.
    """
    instance_ids = list(set(parameters[self.PARAM_INSTANCE_IDS]))

    logger.info('Terminating instances: ' + ' '.join(instance_ids))
    ec2 = self.ec2_client(parameters)
    terminated_instance_ids = []
    try:
      ec2.terminate_instances(InstanceIds=instance_ids)
      terminated_instance_ids = instance_ids
    except ClientError as exception:
      if self.is_error_code(exception, 'InvalidInstanceID.NotFound'):
        for instance_id in instance_ids:
          try:
            ec2.terminate_instances(InstanceIds=[instance_id])
            terminated_instance_ids.append(instance_id)
          except ClientError as e2:
            if self.is_error_code(e2, 'InvalidInstanceID.NotFound'):
              logger.info('Instance not found when terminating: {0}'
                          .format(instance_id))
            else:
              logger.info('Error terminating instance {0}: {1}'
                           .format(instance_id, e2.message))
      else:
        raise exception

    if terminated_instance_ids:
      ec2_waiter = ec2.get_waiter('instance_terminated')
      ec2_waiter.wait(InstanceIds=terminated_instance_ids,
                      WaiterConfig={'MaxAttempts': 8})

  def does_address_exist(self, parameters):
    """Does nothing.

    Args:
      parameters: A dict that contains the Elastic IP to check for existence.
    Returns:
      True if the given Elastic IP has been allocated, and False otherwise.
    """
    return False

  def does_image_exist(self, parameters):
    """Does nothing.

    Args:
      parameters: A dict that contains the machine ID to check for existence.
    Returns:
      True if the machine ID exists, False otherwise.
    """
    return True

  def does_disk_exist(self, parameters, disk_name):
    """ Queries Amazon EC2 to see if the specified EBS volume exists.

    Args:
      parameters: A dict that contains the credentials needed to authenticate
        with AWS.
      disk_name: A str naming the EBS volume to check for existence.
    Returns:
      True if the named EBS volume exists, and False otherwise.
    """
    ec2 = self.ec2_client(parameters)
    try:
      ec2.describe_volumes(VolumeIds=[disk_name])
      logger.info('EBS volume {0} does exist'.format(disk_name))
      return True
    except (BotoCoreError, Boto3Error):
      logger.info('EBS volume {0} does not exist'.format(disk_name))
      return False

  def attach_disk(self, parameters, disk_name, instance_id):
    """ Attaches the Elastic Block Store volume specified in 'disk_name' to this
    virtual machine.

    Args:
      parameters: A dict with keys for each parameter needed to connect to AWS.
      disk_name: A str naming the EBS mount to attach to this machine.
      instance_id: A str naming the id of the instance that the disk should be
        attached to. In practice, callers add disks to their own instances.
    Returns:
      The location on the local filesystem where the disk has been attached.
    """
    # In Amazon Web Services, if we're running on a Xen Paravirtualized machine,
    # then devices get added starting at /dev/xvda. If not, they get added at
    # /dev/sda. Find out which one we're on so that we know where the disk will
    # get attached to.
    if glob.glob('/dev/xvd*'):
      mount_point = '/dev/xvdc'
    elif glob.glob('/dev/vd*'):
      mount_point = '/dev/vdc'
    elif glob.glob('/dev/nvme*'):
      mount_point = '/dev/nvme1n1'
    else:
      mount_point = '/dev/sdc'

    ec2 = self.ec2_client(parameters)

    try:
      logger.info('Attaching volume {0} to instance {1}, at {2}'.format(
        disk_name, instance_id, mount_point))
      ec2.attach_volume(VolumeId=disk_name, InstanceId=instance_id,
                        Device=mount_point)
      return mount_point
    except (BotoCoreError, Boto3Error) as exception:
      if self.disk_attached(ec2, disk_name, instance_id):
        return mount_point
      logger.info('An error occurred when trying to attach volume {0} '
        'to instance {1} at {2}'.format(disk_name, instance_id, mount_point))
      self.handle_failure('EC2 response error while attaching volume:' +
        exception.message)

  def disk_attached(self, ec2, disk_name, instance_id):
    """ Check if disk is attached to instance id.

    Args:
      ec2: A boto3 ec2 client.
      disk_name: A str naming the EBS mount to check.
      instance_id: A str naming the id of the instance that the disk should be
        attached to.
    Returns:
      True if the volume is attached to the instance, False if it is not.
    """
    try:
      volumes_response = ec2.describe_volumes(
          VolumeIds=[disk_name],
          Filters=[{
            'Name': 'attachment.instance-id',
            'Values': [instance_id]
          }])
      return bool(volumes_response.get('Volumes', []))
    except (BotoCoreError, Boto3Error) as exception:
      self.handle_failure('EC2 response error while checking attached '
                          'volumes: {}'.format(exception.message))

  def detach_disk(self, parameters, disk_name, instance_id):
    """ Detaches the EBS mount specified in disk_name from the named instance.

    Args:
      parameters: A dict with keys for each parameter needed to connect to AWS.
      disk_name: A str naming the EBS volume to detach.
      instance_id: A str naming the id of the instance that the disk should be
        detached from.
    Returns:
      True if the disk was detached, and False otherwise.
    """
    ec2 = self.ec2_client(parameters)
    try:
      ec2.detach_volume(VolumeId=disk_name, InstanceId=instance_id)
      return True
    except (BotoCoreError, Boto3Error):
      logger.info("Could not detach volume with name {0}".format(disk_name))
      return False

  def does_zone_exist(self, parameters):
    """Does nothing.

    Args:
      parameters: A dict that contains the availability zone to check for
        existence.
    Returns:
      True if the availability zone exists, and False otherwise.
    """
    return True

  def cleanup_state(self, parameters):
    """ Removes nothing for this AppScale deployment.

    Args:
      parameters: A dict with parameters.
    """
    pass

  def ec2_client(self, parameters):
    """
    Get a client for EC2 API.

    Args:
      parameters: A dictionary containing the 'credentials' parameter.
    Returns:
      An instance of a Boto3 client
    """
    return boto3.client('ec2')

  # noinspection PyMethodMayBeStatic
  def handle_failure(self, msg):
    """ Log the specified error message and raise an AgentRuntimeException

    Args:
      msg: An error message to be logged and included in the raised exception.
    Raises:
      AgentRuntimeException Contains the input error message.
    """
    logger.info(msg)
    raise AgentRuntimeException(msg)

  # noinspection PyMethodMayBeStatic
  def is_error_code(self, exception, code):
    """ Test the error code from a botocore exception

    Args:
      exception: A botocore exception
      code: The error code to check for
    Returns:
      True if the error code matched
    """
    error_code = (getattr(exception, 'response', {})
                  .get('Error', {})
                  .get('Code', 'UnknownError'))
    return error_code == code

  def __test_logging(self):
    """ Output a couple of messages at different logging levels"""
    logger.info("ec2agent info log")
    logger.debug("ec2agent debug log")
    logger.warn("ec2agent warning log")
    logger.error("ec2agent error log")
    logger.critical("ec2agent critical log")
    try:
      raise KeyError()
    except KeyError:
      logger.exception("ec2agent exception")
    

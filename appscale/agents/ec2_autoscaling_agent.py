"""
Helper library for EC2 interaction using autoscaling
"""
import boto3
import datetime
import glob
import logging
import time

from botocore.exceptions import BotoCoreError, ClientError
from boto3.exceptions import Boto3Error

from appscale.agents.config import AppScaleState
from appscale.agents.base_agent import AgentConfigurationException
from appscale.agents.base_agent import AgentRuntimeException
from appscale.agents.base_agent import BaseAgent


logger = logging.getLogger(__name__)

class EC2AutoScalingAgent(BaseAgent):
  """
  EC2 autoscaling agent class which can be used to spawn and terminate
  VMs in an EC2 based environment.
  """

  PARAM_AUTOSCALING_GROUP_NAME = 'aws_autoscaling_group'

  REQUIRED_EC2_RUN_INSTANCES_PARAMS = (
      PARAM_AUTOSCALING_GROUP_NAME,
  )

  REQUIRED_EC2_TERMINATE_INSTANCES_PARAMS = (
    PARAM_AUTOSCALING_GROUP_NAME,
    BaseAgent.PARAM_INSTANCE_IDS,
  )

  def assert_credentials_are_valid(self, parameters):
    """Contacts AWS to verify credentials.

    Args:
      parameters: A dict containing nothing.
    Raises:
      AgentConfigurationException: If a test ec2 describe instances call fails.
    """
    ec2 = self.ec2_client()
    try:
      ec2.describe_instances()
    except Boto3Error:
      raise AgentConfigurationException("We couldn't describe " + \
        "instances. Are your credentials valid?")

  def configure_instance_security(self, parameters):
    """
    The user of this agent is expected to provide appropriate security for
    instances via the autoscaling group.

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

    autoscaling_group_name = args.get(self.PARAM_AUTOSCALING_GROUP_NAME)
    if not autoscaling_group_name:
      raise AgentConfigurationException('AutoScaling group name required.')
    params[self.PARAM_AUTOSCALING_GROUP_NAME] = autoscaling_group_name

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
    autoscaling_group_name = AppScaleState.get_infrastructure_option(
        tag="aws_autoscaling_group", keyname=keyname)

    if not autoscaling_group_name:
      raise AgentConfigurationException('AutoScaling group name equired.')

    return {self.PARAM_AUTOSCALING_GROUP_NAME : autoscaling_group_name}

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
      parameters: A dictionary containing a 'aws_autoscaling_group'
        parameter.
      pending: Indicates we also want the pending instances.
    Returns:
      A tuple of the form (public_ips, private_ips, instances) where each
      member is a list.
    """
    autoscaling_group_name = parameters.get(self.PARAM_AUTOSCALING_GROUP_NAME)
    instance_ids = parameters.get(BaseAgent.PARAM_INSTANCE_IDS)

    states = ['running']
    if pending:
      states.append('pending')

    ec2 = self.ec2_client()
    filters = [
      {
        'Name': 'instance-state-name',
        'Values': states
      },
    ]
    if instance_ids:
      filters.append({
        'Name': 'instance-id',
        'Values': instance_ids
      })
    if autoscaling_group_name:
      filters.append({
        'Name': 'aws:autoscaling:groupName',
        'Values': [autoscaling_group_name]
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
        a 'aws_autoscaling_group' parameter.
      security_configured: Uses this boolean value as an heuristic to
        detect brand new AppScale deployments.
      public_ip_needed: Ignored, this agent expected addressing to be
        externally configured.
    Returns:
      A tuple of the form (instances, public_ips, private_ips)
    """
    autoscaling_group_name = parameters.get(self.PARAM_AUTOSCALING_GROUP_NAME)

    logger.info("Starting {0} machines with auto scaling group {1}"
                .format(count, autoscaling_group_name))

    try:
      start_time = datetime.datetime.now()
      autoscaling = self.as_client()

      # Find any existing unprotected instances
      available_instances = []
      desired_capacity = 0
      instance_count = 0
      groups_response = autoscaling.describe_auto_scaling_groups(
          AutoScalingGroupNames=[autoscaling_group_name])
      for autoscaling_group in groups_response.get('AutoScalingGroups', []):
        if autoscaling_group_name != autoscaling_group.get('AutoScalingGroupName'):
          continue

        desired_capacity = autoscaling_group.get('DesiredCapacity', 0)

        for autoscaling_instance in autoscaling_group.get('Instances', []):
          instance_count = instance_count + 1
          if not autoscaling_instance.get('ProtectedFromScaleIn', False):
            available_instances.append(autoscaling_instance.get('InstanceId'))

      if available_instances:
        instance_ids = available_instances[0:count]
      elif instance_count == desired_capacity:
        autoscaling.set_desired_capacity(
            AutoScalingGroupName=autoscaling_group_name,
            DesiredCapacity=desired_capacity + count)

        end_time = datetime.datetime.now() + datetime.timedelta(0, 300)

        available_instances = []
        while datetime.datetime.now() < end_time and len(available_instances) < count:
          logger.info("Waiting for your instances to start...")
          groups_response = autoscaling.describe_auto_scaling_groups(
              AutoScalingGroupNames=[autoscaling_group_name])
          available_instances = []
          for autoscaling_group in groups_response.get('AutoScalingGroups', []):
            if autoscaling_group_name != autoscaling_group.get('AutoScalingGroupName'):
              continue

            for autoscaling_instance in autoscaling_group.get('Instances', []):
              if not autoscaling_instance.get('ProtectedFromScaleIn', False):
                available_instances.append(autoscaling_instance.get('InstanceId'))

          if len(available_instances) < count:
            time.sleep(15)

        instance_ids = available_instances[0:count]
      else:
        return [], [], []

      autoscaling.set_instance_protection(
          InstanceIds=instance_ids,
          AutoScalingGroupName=autoscaling_group_name,
          ProtectedFromScaleIn=True)

      ec2 = self.ec2_client()
      ec2_waiter = ec2.get_waiter('instance_running')
      ec2_waiter.wait(Filters=[{
          'Name': 'aws:autoscaling:groupName',
          'Values': [autoscaling_group_name]
      }])

      describe_parameters = dict(parameters)
      describe_parameters[BaseAgent.PARAM_INSTANCE_IDS] = instance_ids
      public_ips, private_ips, instance_ids = self.describe_instances(
          describe_parameters)

      end_time = datetime.datetime.now()
      total_time = end_time - start_time
      logger.info("Started {0} instances in {1} seconds"
                  .format(count, total_time.seconds))
      return instance_ids, public_ips, private_ips
    except (Boto3Error, BotoCoreError) as exception:
      self.handle_failure('Error while starting instance(s): ' +
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
    autoscaling_group_name = parameters.get(self.PARAM_AUTOSCALING_GROUP_NAME)
    instance_ids = list(set(parameters[self.PARAM_INSTANCE_IDS]))

    logger.info('Terminating instances: ' + ' '.join(instance_ids))
    autoscaling = self.as_client()
    try:
      autoscaling.set_instance_protection(
          InstanceIds=instance_ids,
          AutoScalingGroupName=autoscaling_group_name,
          ProtectedFromScaleIn=False)
    except (Boto3Error, BotoCoreError) as exception:
      self.handle_failure('AutoScaling error un-protecting instance(s): ' +
                          exception.message)

    terminated_instance_ids = []
    for instance_id in instance_ids:
      try:
        autoscaling.terminate_instance_in_auto_scaling_group(
            InstanceId=instance_id,
            ShouldDecrementDesiredCapacity=True)
        terminated_instance_ids.append(instance_id)
      except ClientError as exception:
        logger.info('Error terminating instance {0}: {1}'
                    .format(instance_id, exception.message))

    # Set capacity to terminate all unprotected instances
    groups_response = autoscaling.describe_auto_scaling_groups(
        AutoScalingGroupNames=[autoscaling_group_name])
    for autoscaling_group in groups_response.get('AutoScalingGroups', []):
      if autoscaling_group_name != autoscaling_group.get('AutoScalingGroupName'):
        continue
      desired_capacity = 0

      for autoscaling_instance in autoscaling_group.get('Instances', []):
        if autoscaling_instance.get('ProtectedFromScaleIn', True):
          desired_capacity = desired_capacity + 1

      autoscaling.set_desired_capacity(
        AutoScalingGroupName=autoscaling_group_name,
        DesiredCapacity=desired_capacity)

    if terminated_instance_ids:
      ec2 = self.ec2_client()
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
    ec2 = self.ec2_client()
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

    ec2 = self.ec2_client()

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
    ec2 = self.ec2_client()
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

  def ec2_client(self):
    """
    Get a client for EC2 API.

    Returns:
      An instance of a Boto3 client
    """
    return boto3.client('ec2')

  def as_client(self):
      """
      Get a client for AutoScaling API.

      Returns:
        An instance of a Boto3 client
      """
      return boto3.client('autoscaling')

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
    

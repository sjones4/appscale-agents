class ShellException(Exception):
    """A special Exception class that should be thrown if a shell command is
    executed and has a non-zero return value.
    """
    pass


class BadConfigurationException(Exception):
    """A special Exception class that should be thrown if the user attempts
    to execute a command with malformed arguments.
    """
    pass


class UnknownInfrastructureException(Exception):
    """ A special Exception class that should be thrown if a user is attempting to
    utilize a cloud infrastructure that the AppScale Tools do not support.
    """
    pass

import six
import abc

@six.add_metaclass(abc.ABCMeta)
class VPPAgentExtensionBase(object):

    @abc.abstractmethod
    def initialize(self, manager):
        """Add cross-references to other extensions if required"""
        pass

    @abc.abstractmethod
    def run(self, host, client_factory, vpp_forwarder):
        """Begin threads watching etcd."""
        pass

@six.add_metaclass(abc.ABCMeta)
class MechDriverExtensionBase(object):
    @abc.abstractmethod
    def initialize(self, manager):
        """Add cross-references to other extensions if required"""
        pass

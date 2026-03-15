import abc
from fogjack.core.base import BaseModule

class CloudModule(BaseModule, abc.ABC):
    """Abstract base for cloud provider modules"""
    @abc.abstractmethod
    def authenticate(self, *args, **kwargs):
        pass

    @abc.abstractmethod
    def enumerate_resources(self):
        pass

    @abc.abstractmethod
    def check_misconfig(self):
        pass

    @abc.abstractmethod
    def exploit(self, **kwargs):
        pass
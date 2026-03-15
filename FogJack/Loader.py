import pkgutil
import importlib
import logging
from fogjack.core.base import BaseModule


class ModuleLoader:
    """
    Discovers and instantiates modules under fogjack.modules and fogjack.plugins.
    """
    def __init__(self, config: dict):
        self.config = config
        self.modules = {}
        self.logger = logging.getLogger(__name__)
        self._discover('fogjack.modules')
        self._discover('fogjack.plugins')

    def _discover(self, package_name: str):
        try:
            pkg = importlib.import_module(package_name)
        except ImportError:
            return

        for finder, name, ispkg in pkgutil.iter_modules(pkg.__path__):
            full_name = f"{package_name}.{name}"
            try:
                module = importlib.import_module(full_name)
            except Exception as e:
                self.logger.debug(f"Failed to import {full_name}: {e}")
                continue

            for attr in dir(module):
                obj = getattr(module, attr)
                if isinstance(obj, type) and issubclass(obj, BaseModule) and obj is not BaseModule:
                    instance = obj(config=self.config)
                    self.modules[instance.name] = instance
                    self.logger.debug(f"Loaded module: {instance.name}")

    def get_module(self, name: str):
        """Retrieve a module instance by its registered name."""
        if name not in self.modules:
            raise KeyError(f"Module not found: {name}")
        return self.modules[name]

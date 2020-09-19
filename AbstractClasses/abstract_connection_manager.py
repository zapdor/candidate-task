from abc import ABC, abstractmethod
from collections import namedtuple
from general_tools import create_logger_with_prefix


class AbstractConnectionContextManager(ABC):
    _CONNECTION_HANDLES_CLASS_NAME = "ConnectionHandles"
    _SERVER_HANDLE = "server_handle"
    _DOMAIN_HANDLE = "domain_handle"
    _CONNECTION_HANDLES_NAMES = [_SERVER_HANDLE, _DOMAIN_HANDLE]

    def __init__(self, target, handles_manager_func=lambda connection, handle: None):
        self.logger = create_logger_with_prefix("MS_RPC_Connection Manager")
        self.__dict__.update(target._asdict())
        self.__dict__.update(vars(target.options))
        self._handles_interface = namedtuple(self._CONNECTION_HANDLES_CLASS_NAME, self._CONNECTION_HANDLES_NAMES)
        self._handles_manager_func = handles_manager_func

        self._handles = None
        self.domain_name = None
        self.domain_handle = None
        self.connection = None

    def __enter__(self):
        self.handles, self.connection, self.domain_name = self.connect()
        self.domain_name = self.handles[0]

        return self.domain_handle

    def __exit__(self, exc_type, exc_val, exc_tb):
        if not self.connection:
            return

        for name, handle in self.handles._asdict().items():
            if not handle:
                continue

            self._handles_manager_func(self.connection, handle)

        self.connection.disconnect()

    @property
    def handles(self):
        return self._handles

    @handles.setter
    def handles(self, new_handles):
        if len(new_handles) != len(self._CONNECTION_HANDLES_NAMES):
            raise ValueError(f"Expecting the following handles: {self._CONNECTION_HANDLES_NAMES}")

        self._handles = self._handles_interface(*new_handles)

    @abstractmethod
    def connect(self):
        pass

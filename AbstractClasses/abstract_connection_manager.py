from abc import ABC, abstractmethod
from collections import namedtuple
from general_tools import create_logger_with_prefix


class AbstractConnectionContextManager(ABC):
    """
    Interface for RPC Connection Managers.
    Acts as Context Manager.
    This allows using the concrete connection managers using "with", like file context managers.
    It will automagically open and close the connection once communication is over.

    Example usage:
        with concrete_connection_manager(*args) as connection:
            do_some_communication_or_processing
    """
    _CONNECTION_HANDLES_CLASS_NAME = "ConnectionHandles"
    _SERVER_HANDLE = "server_handle"
    _DOMAIN_HANDLE = "domain_handle"
    _CONNECTION_HANDLES_NAMES = [_SERVER_HANDLE, _DOMAIN_HANDLE]

    def __init__(self, target, handles_manager_func=lambda connection, handle: None):
        """
        :param target: the
         :type AD_Objects.Target
        :param handles_manager_func:
        """
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
        try:
            self.handles, self.connection, self.domain_name = self.connect()
        except Exception as err:
            self.close_connection()
            raise err

        self.logger.debug(f"Connected to domain {self.domain_name}.")
        self.domain_handle = self.handles[0]

        return (self.connection, self.domain_handle), self.domain_name

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close_connection()
        self.logger.debug(f"Disconnected from domain {self.domain_name} successfully.")

    def close_connection(self):
        if not self.connection:
            return

        for name, handle in self.handles._asdict().items():
            try:
                self._handles_manager_func(self.connection, handle)
            except:
                pass

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

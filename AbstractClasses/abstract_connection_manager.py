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

    # region ---------- Class interface ----------

    _CONNECTION_HANDLES_CLASS_NAME = "ConnectionHandles"
    _SERVER_HANDLE = "server_handle"
    _DOMAIN_HANDLE = "domain_handle"
    _CONNECTION_HANDLES_NAMES = [_SERVER_HANDLE, _DOMAIN_HANDLE]

    def __init__(self, target, handles_manager_closing_func=lambda connection, handle: None):
        """
        :param target: The targetted domain
         :type target: AD_Objects.Target
        :param handles_manager_closing_func: A function that closes handles. needed for closing them automatically.
         :type handles_manager_closing_func: func(connection, handle) -> void
        """
        self.logger = create_logger_with_prefix("RPC_Connection Manager")
        self.__dict__.update(target._asdict())
        self.__dict__.update(vars(target.options))
        self._handles_interface = namedtuple(self._CONNECTION_HANDLES_CLASS_NAME, self._CONNECTION_HANDLES_NAMES)
        self._handles_manager_func = handles_manager_closing_func

        self._handles = None
        self.domain_name = None
        self.domain_handle = None
        self.connection = None

    def close_connection(self):
        if not self.connection:
            return

        for name, handle in self.handles._asdict().items():
            try:
                self._handles_manager_func(self.connection, handle)
            except:
                pass

        self.connection.disconnect()

    @abstractmethod
    def connect(self):
        pass

    # endregion ---------- Class interface ----------
    # region ---------- properties ----------

    @property
    def handles(self):
        return self._handles

    @handles.setter
    def handles(self, new_handles):
        if len(new_handles) != len(self._CONNECTION_HANDLES_NAMES):
            raise ValueError(f"Expecting the following handles: {self._CONNECTION_HANDLES_NAMES}")

        self._handles = self._handles_interface(*new_handles)

    # endregion ---------- properties ----------
    # region ---------- connection context manager ----------

    def __enter__(self):
        self.logger.debug("Starting connection!")
        try:
            self.handles, self.connection, self.domain_name = self.connect()
        except Exception as err:
            self.close_connection()
            raise err

        self.logger.debug(f"Connected to domain {self.domain_name} successfully.")
        self.domain_handle = self.handles[0]

        return (self.connection, self.domain_handle), self.domain_name

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close_connection()
        self.logger.debug(f"Disconnected from domain {self.domain_name} successfully.")

    # endregion ---------- connection context manager ----------

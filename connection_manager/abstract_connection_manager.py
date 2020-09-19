from general_tools import create_logger_with_prefix


class AbstractConnectionContextManager:
    def __init__(self, target):
        self.logger = create_logger_with_prefix("MS_RPC_Connection Manager")
        self.__dict__.update(target._asdict())
        self.connection = None

    def __enter__(self):
        self.connection = self.connect()

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.connection:
            self.connection.disconnect()

    @property
    def connection(self):
        return self._connection

    @connection.setter
    def connection(self, new_connection):
        self._connection = new_connection

    def connect(self):
        raise NotImplementedError

    def disconnect(self):
        raise NotImplementedError

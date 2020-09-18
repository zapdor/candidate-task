from impacket.dcerpc.v5 import epm, samr, transport

from general_tools import create_logger_with_prefix
from samr_client.abstract_connection_manager import AbstractConnectionContextManager


class MS_RPC_ConnectionManager(AbstractConnectionContextManager):
    def __init__(self, target):
        super().__init__(target)
        self.logger = create_logger_with_prefix("MS_RPC_Connection Manager")

    def connect(self):
        return self._dce_connect()

    def _config_rpc_transport(self):
        if self.options.targetIp is not None:
            stringBinding = epm.hept_map(self.options.targetIp, samr.MSRPC_UUID_SAMR, protocol='ncacn_np')
        else:
            stringBinding = epm.hept_map(self.options.dc_host, samr.MSRPC_UUID_SAMR, protocol='ncacn_np')
        rpctransport = transport.DCERPCTransportFactory(stringBinding)
        rpctransport.set_dport(self.__port)

        if self.options.dc_ip is not None:
            rpctransport.setRemoteHost(self.options.dc_ip)
            rpctransport.setRemoteName(self.options.dc_host)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash,
                                         self.__nthash, self.__aesKey)

        rpctransport.set_kerberos(self.__doKerberos, self.options.dc_host or self.options.target_ip)
        return rpctransport

    def _dce_connect(self):
        rpctransport = self._config_rpc_transport()
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        return dce

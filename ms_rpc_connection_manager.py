from impacket.dcerpc.v5 import epm, samr, transport

from general_tools import create_logger_with_prefix
from AbstractClasses.abstract_connection_manager import AbstractConnectionContextManager


class MS_RPC_ConnectionManager(AbstractConnectionContextManager):
    def __init__(self, target):
        super().__init__(target)
        self.logger = create_logger_with_prefix("MS_RPC_Connection Manager")

    def connect(self):
        return self._dce_connect()

    def _config_rpc_transport(self):
        if self.target_ip is not None:
            stringBinding = epm.hept_map(self.target_ip, samr.MSRPC_UUID_SAMR, protocol='ncacn_np')
        else:
            stringBinding = epm.hept_map(self.dc_host, samr.MSRPC_UUID_SAMR, protocol='ncacn_np')
        rpctransport = transport.DCERPCTransportFactory(stringBinding)
        rpctransport.set_dport(self.port)

        if self.dc_ip is not None:
            rpctransport.setRemoteHost(self.dc_ip)
            rpctransport.setRemoteName(self.dc_host)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username, self.password, self.domain, self.lmhash,
                                         self.nthash, self.aesKey)

        rpctransport.set_kerberos(self.k, self.dc_host or self.target_ip)
        return rpctransport

    def _dce_connect(self):
        rpctransport = self._config_rpc_transport()
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        return dce

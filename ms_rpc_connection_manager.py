from impacket.dcerpc.v5 import epm, samr, transport

from general_tools import create_logger_with_prefix
from AbstractClasses.abstract_connection_manager import AbstractConnectionContextManager


class MS_RPC_ConnectionManager(AbstractConnectionContextManager):
    """
    Connection Manager for Microsoft Security Account Manager API.
    """
    SERVER_HANDLE = "ServerHandle"
    DOMAIN_HANDLE = "DomainHandle"
    DOMAIN_ID = "DomainId"

    def __init__(self, target):
        super().__init__(target, handles_manager_func=samr.hSamrCloseHandle)
        self.logger = create_logger_with_prefix("MS_RPC_Connection Manager")

    def connect(self):
        dce = self._dce_connect()
        server_handle = self._get_server_handle(dce)
        domain_name, domain_handle = self._get_domain_name_and_handle(dce, server_handle)

        return (domain_handle, server_handle), dce, domain_name

    def _config_rpc_transport(self):
        string_binding = epm.hept_map(self.target_ip, samr.MSRPC_UUID_SAMR, protocol='ncacn_np')

        rpctransport = transport.DCERPCTransportFactory(string_binding)
        rpctransport.set_dport(self.port)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username, self.password, self.target_ip, self.lmhash,
                                         self.nthash, self.aesKey)

        rpctransport.set_kerberos(self.k, self.dc_ip)
        return rpctransport

    def _dce_connect(self):
        rpctransport = self._config_rpc_transport()
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        return dce

    def _get_server_handle(self, dce):
        samr_connect_resp = samr.hSamrConnect(dce)
        server_handle = samr_connect_resp[self.SERVER_HANDLE]

        return server_handle

    def _get_domain_name_and_handle(self, dce, server_handle):
        samr_enum_resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)

        all_domains = samr_enum_resp['Buffer']['Buffer']
        available_domain_names = [domain['Name'] for domain in all_domains if domain['Name'].lower() != 'builtin']
        if len(available_domain_names) > 1:
            raise ConnectionError(f"Only support 1 domain, but more than 1 found: {', '.join(available_domain_names)}")
        elif len(available_domain_names) == 0:
            raise ConnectionError(f"No domain was found!")

        domain_name = available_domain_names[0]
        self.logger.info(f"Found domain: {domain_name}")
        domain_handle = self._open_domain_handle(dce, server_handle, domain_name)

        return domain_name, domain_handle

    def _open_domain_handle(self, dce, server_handle, domain_name):
        lookup_domain_resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
        domain_sid = lookup_domain_resp[self.DOMAIN_ID]

        self.logger.debug(f"Opening domain {domain_name}...")

        open_domain_response = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)
        domain_handle = open_domain_response[self.DOMAIN_HANDLE]

        self.logger.debug(f"Domain {domain_name} opened!")

        return domain_handle

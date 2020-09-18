from logging import DEBUG

from impacket.smbconnection import SMBConnection

from general_tools import create_logger_with_prefix


class MS_RPC_ConnectionManager():
    def __init__(self, target):
        self.logger = create_logger_with_prefix("MS_RPC_Connection Manager")
        self.__dict__.update(target._asdict())

    def connect(self):
        try:
            smb_client = SMBConnection(self.address, self.options.target_ip, sess_port=int(self.options.port))
            if self.options.k is True:
                smb_client.kerberosLogin(self.username, self.password, self.domain, self.lmhash, self.nthash,
                                         self.options.aesKey, self.options.dc_ip)
            else:
                smb_client.login(self.username, self.password, self.domain, self.lmhash, self.nthash)

        except Exception as e:
            if self.logger.getLogger().level == DEBUG:
                import traceback
                traceback.print_exc()

            self.logger.error(str(e))

        # TODO - rpc, dce

    def _create_rpc_transport(self):
        pass

    def _dce_connect(self):
        pass

    def close_connection(self):
        pass

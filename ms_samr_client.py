import sys
import argparse
import re
from cmd import Cmd
from logging import DEBUG
from impacket import version as impacket_version

from active_directory_tools.AD_Objects import Target
from general_tools import create_logger_with_prefix, get_random_string
from connection_manager.ms_rpc_connection_manager import MS_RPC_ConnectionManager


class MS_SAMR_Client(Cmd):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logger = create_logger_with_prefix("MS_SAMR Client")

        options = self.parse_args(self.logger)

        self.file = getattr(options, "file", None)
        self._target = self.process_target(options, self.logger)
        self.connection_manager = MS_RPC_ConnectionManager(self.target)

    def run(self):
        self.connection_manager.connect()

        if self.file is not None:
            self.logger.info("Executing commands from %s" % self.file.name)
            for line in self.file.readlines():
                if line[0] != '#':
                    print("# %s" % line, end=' ')
                    self.onecmd(line)
                else:
                    print(line, end=' ')
        else:
            self.cmdloop()

    # region ---------- properties ----------

    @property
    def file(self):
        return self._file

    @file.setter
    def file(self, other_file):
        self._file = other_file

    @property
    def target(self):
        return self._target

    @target.setter
    def target(self):
        raise RuntimeError("Impossible to replace initial target!")

    # endregion ---------- properties ----------
    # region ---------- parsing ----------

    @staticmethod
    def parse_args(logger=None):
        if not logger:
            logger = create_logger_with_prefix("Args Parser")

        logger.info("Starting to parse arguments.")

        parser = argparse.ArgumentParser(add_help=True,
                                         description="SMB client arg_parser implementation.")

        parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
        parser.add_argument('-file', type=argparse.FileType('r'),
                            help='input file with commands to execute in the mini shell')
        parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

        authentication_group = parser.add_argument_group('authentication')

        authentication_group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH",
                                          help='NTLM hashes, format is LMHASH:NTHASH')
        authentication_group.add_argument('-no-pass', action="store_true",
                                          help='don\'t ask for password (useful for -k)')
        authentication_group.add_argument('-k', action="store_true",
                                          help='Use Kerberos authentication. Grabs credentials from ccache file '
                                               '(KRB5CCNAME) based on target parameters. If valid credentials '
                                               'cannot be found, it will use the ones specified in the command '
                                               'line')
        authentication_group.add_argument('-aesKey', action="store", metavar="hex key",
                                          help='AES key to use for Kerberos Authentication '
                                               '(128 or 256 bits)')

        authentication_group = parser.add_argument_group('connection')

        authentication_group.add_argument('-dc-ip', action='store', metavar="ip address",
                                          help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
                                               'the target parameter')
        authentication_group.add_argument('-target-ip', action='store', metavar="ip address",
                                          help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                                               'This is useful when target is the NetBIOS name and you cannot resolve it')
        authentication_group.add_argument('-port', choices=['139', '445'], nargs='?', default='445',
                                          metavar="destination port",
                                          help='Destination port to connect to SMB Server. If omitted it will use 445 by default')

        if len(sys.argv) == 1:
            parser.print_help()
            print("No arguments given - need at least target to start.")
            args = input("Please add arguments: ")
            options = parser.parse_args([args])

        else:
            options = parser.parse_args()

        if options.debug is True:
            logger.setLevel(DEBUG)
            logger.debug(impacket_version.getInstallationPath())

        logger.info("Finished parsing arguments.")

        return options

    @staticmethod
    def process_target(options, logger=None):
        if not options:
            return

        if not logger:
            logger = create_logger_with_prefix("Target Processor")

        logger.info("Started processing target from given options.")

        domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
            options.target).groups('')

        # In case the password contains '@'
        if '@' in address:
            password = password + '@' + address.rpartition('@')[0]
            address = address.rpartition('@')[2]

        if options.target_ip is None:
            options.target_ip = address

        if domain is None:
            domain = ''

        if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
            from getpass import getpass
            password = getpass("Password:")

        if options.aesKey is not None:
            options.k = True

        if options.hashes is not None:
            lmhash, nthash = options.hashes.split(':')
        else:
            lmhash = ''
            nthash = ''

        target = Target(domain, username, password, address, lmhash, nthash, options)
        logger.info("Finished processing target.")

        return target

    # endregion ---------- parsing ----------
    # region ---------- shell ----------

    USER_TYPES = ["local", "global"]
    prompt = 'MS_SAMR_Client> '
    into = """Welcome to Dor Bareket's 'Remote Microsoft Security Account Manager' Cymptom tool!
    Type ? to list commands"""

    def do_exit(self, input):
        """
        Exit the application. For Windows/Linux use Ctrl+C. For OS-X use Command+C. Otherwise you're all alone.
        :param input:
        """
        print("Bye Mate")
        return True

    def do_add_user(self, user_type, user_name=None):
        """
        Add a new entry to the remote Active Directory domain.
        :param user_type: accepted values: local / group
        :param user_name: if not given, a random username will be created
        """
        if user_type.lower() not in ["local", "group"]:
            print(f"Undefined user_type! Allowed only: {self.USER_TYPES}")
            return False

        if not user_name:
            user_name = self.random_computer_name(user_type)

        print(f"Adding user of type {user_type} with name {user_name} to the remote Active Directory.")

        # TODO

    def do_list_users(self, user_type=None):
        """
        Lists all groups and users of the remote Active Directory domain.
        :param user_type: optional. if not given, all users and groups will be listed. accepted values: local / group
        """
        if user_type and user_type.lower() not in ["local", "group"]:
            print(f"Undefined user_type! Allowed only none or: {self.USER_TYPES}")
            return False

        if not user_type:
            print("Listing all users and groups!")

        elif user_type.lower() == 'group':
            print("Listing all groups!")

        elif user_type.lower() == 'local':
            print("Listing all local users!")

        # TODO

    def default(self, inp):
        print(f"Unknown action: {inp}. Type '?' to list available commands")

    do_EOF = do_exit

    # endregion ---------- shell ----------
    # region ---------- helper functions ----------

    @staticmethod
    def random_computer_name(user_type):
        return get_random_string(length=10, prefix=f"TestUser_{user_type}_")

    # endregion ---------- helper functions ----------


def main():
    samr_client = MS_SAMR_Client()
    samr_client.run()


if __name__ == "__main__":
    main()

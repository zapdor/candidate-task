import argparse
import functools
import re
import sys
from logging import DEBUG

from AD_Objects import Target
from general_tools import create_logger_with_prefix
from impacket import version as impacket_version


class MS_SAMR_OptionsParser:

    @staticmethod
    def parse_args(logger=None):
        if not logger:
            logger = create_logger_with_prefix("Args Parser")

        logger.info("Starting to parse arguments.")

        parser = argparse.ArgumentParser(add_help=True,
                                         description="SMB client arg_parser implementation.")

        parser.add_argument('target', action='store',
                            help='[[domain/]username[:password]@]<targetName or address>')
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
        authentication_group.add_argument('-dc-host', action='store', metavar="hostname",
                                          help='Hostname of the domain controller to use. '
                                               'If ommited, the domain part (FQDN) '
                                               'specified in the account parameter will be used')
        authentication_group.add_argument('-target-ip', action='store', metavar="ip address",
                                          help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                                               'This is useful when target is the NetBIOS name and you cannot resolve it')
        authentication_group.add_argument('-port', choices=['139', '445'], nargs='?', default='445',
                                          metavar="destination port",
                                          help='Destination port to connect to SMB Server. If omitted it will use 445 by default')

        if len(sys.argv) == 1:
            parser.print_help()
            print("No arguments given - need at least target to start.")
            args = input("Please add arguments: ").split()
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


class MS_SAMR_ShellDecorators:

    def split_args(func):
        @functools.wraps(func)
        def wrapper(instance, args_str, *args, **kwargs):
            args_list = tuple(args_str.split() or [None] + list(args))
            func(instance, *args_list, **kwargs)

        return wrapper

    def prompt_entry_type_if_needed(err_msg):
        def inner(func):
            @functools.wraps(func)
            def wrapper(instance, entry_type, *args, **kwargs):
                while not entry_type:
                    inp = input(err_msg)
                    entry_type = inp.split()[0] if inp else ''

                func(instance, entry_type, *args, **kwargs)

            return wrapper

        return inner

    def validate_entry_type(err_msg, allow_no_entry_type=False, num_params=1):
        def inner(func):
            @functools.wraps(func)
            def wrapper(instance, entry_type, *args, **kwargs):
                if (allow_no_entry_type and not entry_type) \
                        or (entry_type.lower() in instance.ENTRY_TYPES):
                    if num_params - 1 > len(args):
                        args = [None] * (num_params - 1)
                    return func(instance, entry_type, *args, **kwargs)

                print(err_msg)

            return wrapper

        return inner

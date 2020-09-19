from cmd import Cmd

from general_tools import create_logger_with_prefix, get_random_string
from ms_rpc_connection_manager import MS_RPC_ConnectionManager
from ms_samr_parser import MS_SAMR_OptionsParser as options_parser, MS_SAMR_ShellDecorators as shell_decorators


class MS_SAMR_Client(Cmd):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logger = create_logger_with_prefix("MS_SAMR Client")

        options = options_parser.parse_args(self.logger)

        self.file = getattr(options, "file", None)
        self._target = options_parser.process_target(options, self.logger)
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
    # region ---------- shell ----------

    LOCAL = "local"
    GROUP = "group"
    USER_TYPES = [LOCAL, GROUP]

    prompt = f"{'MS_SAMR_CLIENT'}> "
    intro = """Welcome to Dor Bareket's 'Remote Microsoft Security Account Manager'. 
    This tool was created as part of the candidate task for "Cymptom".
    Hope you enjoy!
    
    Type ? to list commands"""

    PLEASE_INSET_USER_TYPE_MSG = f"Please choose which user type from {USER_TYPES}: "
    UNDEFINED_USER_TYPE = f"Undefined user_type! Allowed only: {USER_TYPES}"

    def do_exit(self, input):
        """
        Exit the application. For Windows/Linux use Ctrl+C. For OS-X use Command+C. Otherwise you're all alone.
        :param input:
        """
        print("Bye Mate")
        return True

    @shell_decorators.prompt_user_type_if_needed(err_msg=PLEASE_INSET_USER_TYPE_MSG)
    @shell_decorators.validate_user_type(err_msg=UNDEFINED_USER_TYPE)
    def do_add_user(self, user_type, user_name=None):
        """
        Add a new entry to the remote Active Directory domain.
        :param user_type: accepted values: local / group
        :param user_name: if not given, a random username will be created
        """
        if not user_name:
            user_name = self.random_computer_name(user_type)

        print(f"Adding user of type '{user_type}' with name '{user_name}' to the remote Active Directory.")

        # TODO

    @shell_decorators.prompt_user_type_if_needed(err_msg=PLEASE_INSET_USER_TYPE_MSG)
    @shell_decorators.validate_user_type(err_msg=UNDEFINED_USER_TYPE, allow_no_user_type=True)
    def do_list_users(self, user_type=None):
        """
        Lists all groups and users of the remote Active Directory domain.
        :param user_type: optional. if not given, all users and groups will be listed. accepted values: local / group
        """
        if not user_type:
            print("Listing all users and groups!")

        elif user_type.lower() == self.GROUP:
            print("Listing all groups!")

        elif user_type.lower() == self.LOCAL:
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

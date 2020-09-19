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
    ENTRY_TYPES = [LOCAL, GROUP]

    prompt = f"{'MS_SAMR_CLIENT'}> "
    intro = """Welcome to Dor Bareket's 'Remote Microsoft Security Account Manager'. 
    This tool was created as part of the candidate task for "Cymptom".
    Hope you enjoy!
    
    Type ? to list commands"""

    PLEASE_INSET_ENTRY_TYPE_MSG = f"Please choose which entry type from {ENTRY_TYPES}: "
    UNDEFINED_ENTRY_TYPE = f"Undefined entry_type! Allowed only: {ENTRY_TYPES}"

    def do_exit(self, input):
        """
        Exit the application.
        Keyboard Shortcuts: For Windows/Linux use Ctrl+C. For OS-X use Command+C. Otherwise just type 'exit'.
        """
        print("Bye Mate")
        return True

    @shell_decorators.prompt_entry_type_if_needed(err_msg=PLEASE_INSET_ENTRY_TYPE_MSG)
    @shell_decorators.validate_entry_type(err_msg=UNDEFINED_ENTRY_TYPE)
    def do_add_entry(self, entry_type, entry_name=None):
        """
        Add a new entry to the remote Active Directory domain.
        :param entry_type: accepted values: local / group
        :param entry_name: if not given, a random entry name will be created
        """
        if not entry_name:
            entry_name = self.random_computer_name(entry_type)

        print(f"Adding entry of type '{entry_type}' with name '{entry_name}' to the remote Active Directory.")

        # TODO

    @shell_decorators.prompt_entry_type_if_needed(err_msg=PLEASE_INSET_ENTRY_TYPE_MSG)
    @shell_decorators.validate_entry_type(err_msg=UNDEFINED_ENTRY_TYPE, allow_no_entry_type=True)
    def do_list_entries(self, entry_type=None):
        """
        Lists all groups and local users of the remote Active Directory domain.
        :param entry_type: optional. if not given, all local users and groups will be listed. accepted values: local / group
        """
        if not entry_type:
            print("Listing all local users and groups!")

        elif entry_type.lower() == self.GROUP:
            print("Listing all groups!")

        elif entry_type.lower() == self.LOCAL:
            print("Listing all local users!")

        # TODO

    def default(self, inp):
        print(f"Unknown action: {inp}. Type '?' to list available commands")

    do_EOF = do_exit

    # endregion ---------- shell ----------
    # region ---------- helper functions ----------

    @staticmethod
    def random_computer_name(entry_type):
        return get_random_string(length=10, prefix=f"TestUser_{entry_type}_")

    # endregion ---------- helper functions ----------


def main():
    samr_client = MS_SAMR_Client()
    samr_client.run()


if __name__ == "__main__":
    main()

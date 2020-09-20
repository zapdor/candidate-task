from cmd import Cmd
from pprint import pprint

from AD_Objects import User, Group
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
        self.connection_manager = lambda: MS_RPC_ConnectionManager(self.target)

    def run(self):
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
    ENTRY_TYPES_TO_OBJECTS = {LOCAL: User,
                              GROUP: Group}
    ENTRY_TYPES = ENTRY_TYPES_TO_OBJECTS.keys()

    prompt = f"{'MS_SAMR_CLIENT'}> "
    intro = """Welcome to Dor Bareket's 'Remote Microsoft Security Account Manager'. 
    This tool was created as part of the candidate task for "Cymptom".
    Hope you enjoy!
    
    Type ? to list commands"""

    PLEASE_INSET_ENTRY_TYPE_MSG = f"Please choose which entry type from {', '.join(ENTRY_TYPES)}: "
    UNDEFINED_ENTRY_TYPE = f"Undefined entry_type! Allowed only: {', '.join(ENTRY_TYPES)}"

    def do_exit(self, input):
        """
        Exit the application.
        Keyboard Shortcuts: For Windows/Linux use Ctrl+C. For OS-X use Command+C. Otherwise just type 'exit'.
        """
        print("Bye Mate")
        return True

    @shell_decorators.split_args
    @shell_decorators.prompt_entry_type_if_needed(err_msg=PLEASE_INSET_ENTRY_TYPE_MSG)
    @shell_decorators.validate_entry_type(err_msg=UNDEFINED_ENTRY_TYPE, num_params=2)
    def do_add_entry(self, entry_type, entry_name=None):
        """
        Add a new entry to the remote Active Directory domain.
        :param entry_type: accepted values: local / group
        :param entry_name: if not given, a random entry name will be created
        """
        if not entry_name:
            entry_name = self.random_computer_name(entry_type)

        print(f"Adding entry of type '{entry_type}' with name '{entry_name}' to the remote Active Directory.")

        with self.connection_manager() as (connection, domain_name):
            self._add_entry(connection, entry_type, entry_name)

    @shell_decorators.split_args
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

        with self.connection_manager() as (connection, domain_name):
            entries_list = self._list_entries(connection, entry_type)

        pprint(entries_list)

    def default(self, inp):
        print(f"Unknown action: {inp}. Type '?' to list available commands")

    do_EOF = do_exit

    # endregion ---------- shell ----------
    # region ---------- action functions ----------

    def _add_entry(self, connection, entry_type, entry_name):
        self.logger.debug(f"Adding entry of type {entry_type} with name {entry_name}.")
        created = None
        try:
            created = self.ENTRY_TYPES_TO_OBJECTS[entry_type].create(connection, entry_name)
        except Exception as err:
            print(f"Could not create {entry_name}. AD Error message: {str(err)}")
        else:
            print(f"Entry added successfully!")

    def _list_entries(self, connection, entry_type):
        self.logger.debug(f"Listing entries of type {entry_type}...")
        entries_list = self.ENTRY_TYPES_TO_OBJECTS[entry_type].list_all(connection)

        return entries_list

    # endregion ---------- action functions ----------
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

# TODO - FIXME - docstring
# TODO - FIXME - unit-tests

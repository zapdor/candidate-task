from logging import DEBUG

from general_tools import create_logger_with_prefix
from ms_rpc_connection_manager import MS_RPC_ConnectionManager
from ms_samr_parser import MS_SAMR_OptionsParser as options_parser
from tests.conftest import *

pytestmark = [pytest.mark.unit_tests]
logger = create_logger_with_prefix("SAMR_CLIENT_UNIT_TESTS", DEBUG)


class Test_SAMR_Parser:

    @pytest.mark.parametrize("args, expected_options", [
        ((DEFAULT_TARGET,), PARSER_EXPECTED_OPTIONS)
    ])
    def test_parse_args(self, args, expected_options):
        options = options_parser.parse_args(args)
        non_empty_options = {op: val for op, val in vars(options).items() if val}

        assert non_empty_options == expected_options, "Parsed options do not match expected!"

    def test_process_target(self, options_namespace, target_asdict):
        target_asdict["options"] = options_namespace
        target = options_parser.process_target(options_namespace)

        assert target._asdict() == target_asdict, "Processed target is different than expected!"


class Test_SAMR_ConnectionManager:

    def test_connection_manager_with_mocked_creds(self, mock_env_creds, target):
        connection_manager = MS_RPC_ConnectionManager(target)
        assert connection_manager is not None and type(connection_manager) == MS_RPC_ConnectionManager

    def test_connect_using_connection_manager_with_mocked_creds(self, mock_env_creds, target):
        connection_manager = lambda: MS_RPC_ConnectionManager(target)
        try:
            with connection_manager() as (connection, domain_name):
                pass
        except Exception as err:
            pytest.fail("Unexpected exception was raised when trying to connect using connection manager."
                        f"error message: {str(err)}")


@pytest.fixture(autouse=True, scope="class")
def _create_client_with_mocked_creds(request, mock_env_creds):
    try:
        request.cls.samr_client = MS_SAMR_Client(DEFAULT_TARGET)
    except Exception as err:
        pytest.fail("Unexpected exception was raised when trying to create a new samr_client."
                    f"error message: {str(err)}")


class Test_SAMR_Client:

    @pytest.mark.parametrize("entry_type", MS_SAMR_Client.ENTRY_TYPES)
    def test_list_all_entries(self, entry_type, capsys):
        logger.debug("Getting list of entries:")
        self.samr_client.do_list_entries(f"{entry_type}")
        entries_by_type = get_entries_list_from_stdout(capsys)

        logger.debug(f"Entries list: {entries_by_type}")

        assert entry_type in entries_by_type, f"No entries of type {entry_type} were found!"
        assert len(entries_by_type[entry_type]) > 0, f"Found 0 entries of type {entry_type}, which is impossible!"

    @pytest.mark.parametrize("entry_type", MS_SAMR_Client.ENTRY_TYPES)
    def test_add_user(self, entry_type, random_computer_name_fixture, capsys):
        entry_name_to_add = random_computer_name_fixture

        logger.debug(f"Adding {entry_type} {entry_name_to_add}")
        self.samr_client.do_add_entry(args_str=f"{entry_type} {entry_name_to_add}")

        logger.debug("Entry added! Asserting success")
        self.samr_client.do_list_entries(f"{entry_type}")
        entries_by_type = get_entries_list_from_stdout(capsys)

        assert entry_name_to_add in entries_by_type[entry_type], "The entry was not created."

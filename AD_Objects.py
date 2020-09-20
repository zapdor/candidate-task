from abc import ABC, abstractmethod
from collections import namedtuple
from contextlib import contextmanager
from logging import DEBUG

from impacket.dcerpc.v5 import samr
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.nt_errors import STATUS_MORE_ENTRIES
from impacket.smb import MAXIMUM_ALLOWED, STATUS_SUCCESS

from general_tools import create_logger_with_prefix


class Target(namedtuple("CymptomTarget",
                        """
                        domain
                        username
                        password
                        address
                        lmhash
                        nthash
                        options
                        """)):
    pass


class ADEntry(ABC):
    HANDLE = 'ABSTRACT'
    INFO_CLASS = 'ABSTRACT'
    INFO_LOCATION_IN_BUFFER = 'General'
    ID_LOCATION = 'RelativeId'

    # Abstract functions
    CREATE_FUNC = None
    OPEN_FUNC = None
    PROCESS_INFO_FUNC = None
    ENUMERATE_FUNC = None

    def __init__(self, name=None, uid=None, entry_info=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = name
        self.uid = uid
        self.entry_info = entry_info

    @classmethod
    def get_AD_logger(cls):
        return create_logger_with_prefix(cls.__name__)

    @classmethod
    @contextmanager
    def process_raw_entry_info(cls, connection, entry_raw_info):
        entry_resp = cls.OPEN_FUNC(*connection, MAXIMUM_ALLOWED, entry_raw_info[cls.ID_LOCATION])
        entry_handle = entry_resp[cls.HANDLE]
        dce = connection[0]
        entry_info = cls.PROCESS_INFO_FUNC(dce, entry_handle)
        try:
            yield entry_info
        finally:
            samr.hSamrCloseHandle(dce, entry_handle)

    @classmethod
    def create(cls, connection, name=None, entry_raw_info=None):
        if all(v is not None for v in [name, entry_raw_info]):
            raise RuntimeError("Create can work on either name or entry_raw_info, but not both!")

        if all(v is None for v in [name, entry_raw_info]):
            raise RuntimeError("Create must receive either name or entry_raw_info to create an AD entry!")

        if entry_raw_info is not None:
            return cls._create_entry_from_raw_info(connection, entry_raw_info)

        return cls._create_entry_from_name(connection, name)

    @classmethod
    def _create_entry_from_name(cls, connection, name):
        create_resp = cls.CREATE_FUNC(*connection, name)
        uid = create_resp[cls.ID_LOCATION]
        entry_obj = cls(name, uid, None)

        return entry_obj

    @classmethod
    def _create_entry_from_raw_info(cls, connection, entry_raw_info):
        name = entry_raw_info["Name"]
        uid = entry_raw_info["RelativeId"]
        with cls.process_raw_entry_info(connection, entry_raw_info) as entry_info:
            entry_obj = cls(name, uid, entry_info["Buffer"][cls.INFO_LOCATION_IN_BUFFER])

        return entry_obj

    @classmethod
    def list_all(cls, connection):
        entries_list = []
        page = 1

        status = STATUS_MORE_ENTRIES
        while status == STATUS_MORE_ENTRIES:
            try:
                resp = cls.ENUMERATE_FUNC(*connection)
            except DCERPCException as e:
                if str(e).find("STATUS_MORE_ENTRIES") < 0:
                    raise
                resp = e.get_packet()

            entries_raw_info = resp["Buffer"]["Buffer"]
            page_entries = [cls.create(connection, entry_raw_info=entry_raw_info) for entry_raw_info in entries_raw_info]

            cls.get_AD_logger().debug(f"Found {len(page_entries)} AD entries of type {cls.__name__} in page {page}")
            page += 1

            entries_list.extend(page_entries)

            try:
                status = resp['ErrorCode']
            except KeyError as err:
                raise RuntimeError(
                    f"Received error on page {page}, while listing entries of type {cls.__name__}. AD Error message: {str(err)}")

            if status != STATUS_SUCCESS:
                raise ConnectionError(f"Received status {status} on page {page} while listing entries of type {cls.__name__}")

        return entries_list


class User(ADEntry):
    HANDLE = 'UserHandle'
    INFO_CLASS = samr.USER_INFORMATION_CLASS.UserAllInformation

    CREATE_FUNC = samr.hSamrCreateUser2InDomain
    OPEN_FUNC = samr.hSamrOpenUser
    PROCESS_INFO_FUNC = samr.hSamrQueryInformationUser2
    ENUMERATE_FUNC = samr.hSamrEnumerateUsersInDomain


class Group(ADEntry):
    HANDLE = 'GroupHandle'
    INFO_CLASS = 'ABSTRACT'

    CREATE_FUNC = samr.hSamrCreateGroupInDomain
    OPEN_FUNC = samr.hSamrOpenGroup
    PROCESS_INFO_FUNC = samr.hSamrQueryInformationGroup
    ENUMERATE_FUNC = samr.hSamrEnumerateGroupsInDomain

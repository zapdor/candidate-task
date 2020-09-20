from abc import ABC, abstractmethod
from collections import namedtuple
from contextlib import contextmanager

from impacket.dcerpc.v5 import samr
from impacket.smb import MAXIMUM_ALLOWED


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
    INFO_LOCATION_IN_BUFFER = 'ABSTRACT'
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

    @contextmanager
    def get_entry_info(self, connection, entry_raw_info):
        entry_resp = self.OPEN_FUNC(*connection, MAXIMUM_ALLOWED, entry_raw_info[self.ID_LOCATION])
        entry_handle = entry_resp[self.HANDLE]
        dce = connection[0]
        entry_info = self.PROCESS_INFO_FUNC(dce, entry_handle)
        try:
            yield entry_info
        finally:
            samr.hSamrCloseHandle(dce, entry_handle)

    @classmethod
    def create(cls, connection, name):
        create_resp = cls.CREATE_FUNC(*connection, name)
        uid = create_resp[cls.ID_LOCATION]
        entry_obj = cls(name, uid, None)

        return entry_obj

    def get(self, connection, entry_raw_info):
        name = entry_raw_info['Name']
        uid = entry_raw_info['RelativeId']
        with self.get_entry_info(connection, entry_raw_info) as entry_info:
            entry_obj = self.__class__(name, uid, entry_info['Buffer'][self.INFO_LOCATION_IN_BUFFER])

        return entry_obj

    def list_all(self, connection):
        entries_list = self.ENUMERATE_FUNC(*connection)

        return entries_list


class User(ADEntry):
    HANDLE = 'UserHandle'

    CREATE_FUNC = samr.hSamrCreateUser2InDomain
    OPEN_FUNC = samr.hSamrOpenUser
    PROCESS_INFO_FUNC = samr.hSamrQueryInformationUser2
    ENUMERATE_FUNC = samr.hSamrEnumerateUsersInDomain


class Group(ADEntry):
    HANDLE = 'GroupHandle'

    CREATE_FUNC = samr.hSamrCreateGroupInDomain
    OPEN_FUNC = samr.hSamrOpenGroup
    PROCESS_INFO_FUNC = samr.hSamrQueryInformationGroup
    ENUMERATE_FUNC = samr.hSamrEnumerateGroupsInDomain

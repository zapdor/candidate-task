from collections import namedtuple


class Target(namedtuple("CymptomTarget", "domain username password address lmhash nthash options")):
    pass


class ADEntry(namedtuple("EntryData", ("name", "uid"))):
    NOT_IMPLEMENTED_ERROR_MESSAGE = "Please implement {func_name} for the desired AD Entry"

    def __new__(cls, name, uid):
        self = super().__new__(cls, name, uid)
        return self

    def add(self):
        raise NotImplementedError(self.NOT_IMPLEMENTED_ERROR_MESSAGE.format(func_name="add"))

    def get(self):
        raise NotImplementedError(self.NOT_IMPLEMENTED_ERROR_MESSAGE.format(func_name="get"))

    def list_all(self):
        raise NotImplementedError(self.NOT_IMPLEMENTED_ERROR_MESSAGE.format(func_name="list_all"))


class User(ADEntry):
    pass


class Group(ADEntry):
    pass

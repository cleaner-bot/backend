from enum import Enum, auto


class Access(Enum):
    NONE = auto()
    SUPPORT = auto()
    DEVELOPER = auto()


users = {
    633993042755452932: Access.DEVELOPER,
    918875640046964797: Access.DEVELOPER,
    # 922118393178517545: Access.SUPPORT,
}


def has_access(user_id: int | str, required: Access = Access.SUPPORT) -> bool:
    if isinstance(user_id, str):
        user_id = int(user_id)
    access = users.get(user_id, Access.NONE)
    return access.value >= required.value

import typing
from enum import Enum

from algorithms.features.base_syscall_feature_extractor import BaseSyscallFeatureExtractor
from dataloader.syscall import Syscall

class BEHAVIOUR(Enum):
    RETURN_ZERO = 1
    NEW_INT = 2


class SyscallToInt(BaseSyscallFeatureExtractor):
    """

        convert system call name to unique integer

    """

    def __init__(self, unknown_syscall_behaviour=BEHAVIOUR.RETURN_ZERO):
        super().__init__()
        if unknown_syscall_behaviour not in BEHAVIOUR:
            raise(ValueError(
                f'Incorrect behaviour given for SyscallToInt Extractor. Choices: {BEHAVIOUR[1]}, {BEHAVIOUR[2]}')
            )

        self._unknown_syscall_behaviour = unknown_syscall_behaviour
        self._syscall_dict = {}

    def train_on(self, syscall: Syscall):
        """

            takes one syscall and assigns integer
            integer is current length of syscall_dict
            keep 0 free for unknown syscalls

        """
        if syscall.name() not in self._syscall_dict:
            self._syscall_dict[syscall.name()] = len(self._syscall_dict) + 1

    def extract(self, syscall: Syscall) -> typing.Tuple[str, list]:
        """

            transforms given syscall name to integer

        """
        try:
            sys_to_int = self._syscall_dict[syscall.name()]
        except KeyError:
            if self._unknown_syscall_behaviour == BEHAVIOUR.NEW_INT:
                self.train_on(syscall)
                sys_to_int = self._syscall_dict[syscall.name()]
            elif self._unknown_syscall_behaviour == BEHAVIOUR.RETURN_ZERO:
                sys_to_int = 0
        return SyscallToInt.get_id(), [sys_to_int]

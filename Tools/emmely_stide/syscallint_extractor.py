import typing
from dataloader.syscall import Syscall
from algorithms.base_syscall_feature_extractor import BaseSyscallFeatureExtractor


class SyscallIntExtractor(BaseSyscallFeatureExtractor):

    def __init__(self):
        super().__init__()
        self._syscall_dict = {}

    def extract(self, syscall: Syscall) -> typing.Tuple[str, int]:
        
        if not syscall.name() in self._syscall_dict:
            self._syscall_dict[syscall._name] = len(self._syscall_dict) + 1
        
        return 'sys_int', self._syscall_dict[syscall._name]




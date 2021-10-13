#from algorithms.base_syscall_feature_extractor import BaseSyscallFeatureExtractor
from Tools.syscall import Syscall

class feature_extractor_stide():

    def __init__(self):
        self._syscall_dict =  {}

    def extract(self, syscall: Syscall):
        if not syscall.name() in self._syscall_dict:
            self._syscall_dict[syscall._name] = len(self._syscall_dict) + 1
        return syscall.name(), self._syscall_dict[syscall._name]



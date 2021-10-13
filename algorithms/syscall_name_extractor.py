import typing

from dataloader.syscall import Syscall
from algorithms.base_syscall_feature_extractor import BaseSyscallFeatureExtractor


class NameExtractor(BaseSyscallFeatureExtractor):

    def extract(self, syscall: Syscall) -> typing.Tuple[str, str]:
        """

        extract name of syscall

        """
        return 'name', syscall.name()

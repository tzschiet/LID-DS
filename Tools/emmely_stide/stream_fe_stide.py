import typing
from algorithms.base_stream_feature_extractor import BaseStreamFeatureExtractor
from collections import  deque


class StreamFeatureExtractorStide(BaseStreamFeatureExtractor):

    def __init__(self):
        super().__init__()
        self._ngram_length = ngram_length
        self._ngram_deque = deque(maxlen=ngram_length)

    def train_on(self, syscall_feature: dict):
        """

        takes features of one system call to train this extraction

        """
        pass

    def fit(self):
        """

        finalizes training

        """
        pass

    def extract(self, syscall_features: dict) -> typing.Tuple[str, object]:
        """

        extracts a feature from a stream of syscall features

        Returns:
        dict: key: name of feature and
              value: value of feature

        """
        pass

    def new_recording(self):
        """

        empty buffers and prepare for next recording

        """
        pass


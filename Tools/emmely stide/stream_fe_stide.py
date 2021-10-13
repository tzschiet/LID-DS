from algorithms.base_stream_feature_extractor import BaseStreamFeatureExtractor
from collections import  deque
from fe_stide import feature_extractor_stide

class stream_feature_extractor_stide():

    def __init__(self):
        self._ngram_length = ngram_length
        self._ngram_deque = deque(maxlen=ngram_length)

    def extract(self, syscall_features: dict) -> tuple:
        k, v = feature_extractor_stide()
        self._ngram_deque.append(v)

        if len(self._ngram_deque) >= self._ngram_length:
            return tuple(self._ngram_deque)

    def new_recording(self):
        self._ngram_deque.clear()

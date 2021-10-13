import stream_fe_stide

class StreamNgramExtractors:

    def __init__(self):
        self._ngram_list = []

    def _collect_features(self, ngram: tuple) -> list:
        self._ngram_list.append(stream_fe_stide())
        return self._ngram_list


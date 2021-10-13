import typing

from gensim.models import KeyedVectors, Word2Vec

from base_syscall_feature_extractor import BaseSyscallFeatureExtractor
from dataloader.syscall import Syscall


class W2VEmbeddingExtractor(BaseSyscallFeatureExtractor):
    def __init__(self, vector_size, epochs, path, force_train, distinct: bool):
        super().__init__()
        self._vector_size = vector_size
        self._epochs = epochs
        self._path = path
        self._force_train = force_train
        self._distinct = distinct
        self.w2vmodel = None
        self._sentences = []
        if not force_train:
            self.load()

    def train_on(self, sentence: list):
        string_sentence = ' '.join(sentence)

        if string_sentence not in self._sentences and not self._distinct:
            self._sentences.append(string_sentence)

    def fit(self):
        if not self.w2vmodel:
            model = Word2Vec(self._sentences, vector_size=self._vector_size, epochs=self._epochs)

            self.w2vmodel = model

    def extract(self, syscall: Syscall) -> typing.Tuple[str, object]:
        try:
            return 'w2v', self.w2vmodel[syscall.name()].tolist()
        except KeyError:
            return 'w2v', [0] * self._vector_size


    def load(self):
        """

            check if word embedding has been created for this scenario

        """
        try:
            self.w2vmodel = KeyedVectors.load(self._path, mmap='r')
            print(f'Loaded embedding: {self._path}')
        except Exception:
            print(f'No embedding found for: {self._path}')

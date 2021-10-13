from collections import deque


class Stide():

    def __init__(self):
        self._deque_ngram = deque


    def train_on(self, input_array: list):

        self._deque_ngram.append()

        if len(self._q_ngram) >= self._ngram_length:
            self._qtuple = tuple(self._q_ngram)
            # print(qtuple)

            if not self._qtuple in self._trainingsset_ngrams:
                self._trainingsset_ngrams.add(self._qtuple)

    def fit(self,):

    def predict(self, input_array:list)-> float:
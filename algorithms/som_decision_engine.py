import math

from matplotlib import pyplot as plt

from base_decision_engine import BaseDecisionEngine
from minisom import MiniSom
from tqdm import tqdm
import numpy as np
from numpy.linalg import norm


class SomDecisionEngine(BaseDecisionEngine):
    def __init__(self, epochs):
        super().__init__()
        self._buffer = []
        self._epochs = epochs
        self._som = None

    def _estimate_som_size(self):
        som_size = round(math.sqrt(
            len(self._buffer)
        ), 0)

        som_size += 1
        return int(som_size)

    def train_on(self, input_array):
        if not input_array in self._buffer:
            self._buffer.append(input_array)

    def fit(self):
        som_size = self._estimate_som_size()
        vector_size = len(self._buffer[0])

        self._som = MiniSom(som_size, som_size, vector_size, random_seed=1)

        for epoch in tqdm(range(self._epochs), desc='Training SOM'):
            for vector in self._buffer:
                self._som.update(vector, self._som.winner(vector), epoch, self._epochs)

    def predict(self, input_array):
        codebook_vector = np.array(self._som.quantization([input_array])[0])
        vector = np.array(input_array)
        distance = norm(vector - codebook_vector)

        return distance

    def show_distance_plot(self):
        plt.figure()
        plt.pcolor(self._som.distance_map(), cmap='gnuplot')
        plt.colorbar()

        plt.show()

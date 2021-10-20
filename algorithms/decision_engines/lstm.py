import torch
import torch.nn as nn
from torch.autograd import Variable

import numpy as np
from tqdm import tqdm

from algorithms.decision_engines.base_decision_engine import BaseDecisionEngine


class LSTM(BaseDecisionEngine):

    def __init__(self,
                 ngram_length,
                 embedding_size,
                 distinct_syscalls,
                 extra_param=0,
                 epochs=300,
                 streaming_window_size=1,
                 architecture=None,
                 predict_on_batch=False,
                 batch_size=1,
                 model_path='Models/',
                 force_train=False):
        self._ngram_length = ngram_length
        self._embedding_size = embedding_size
        self._extra_param = extra_param
        self._batch_size = batch_size
        self._predict_on_batch = predict_on_batch
        self._epochs = epochs
        self._distinct_syscalls = distinct_syscalls
        self._model_path = model_path \
            + f'n{self._ngram_length}-e{self._embedding_size}-p{self._extra_param}-ep{self._epochs}'
        self._training_data = {
            'x': [],
            'y': []
        }
        self._architecture = architecture
        self._lstm_layer = None
        self._device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
        if not force_train:
            self._set_model(self._distinct_syscalls)
            self._lstm.load_state_dict(torch.load(self._model_path))

    def _set_model(self, distinct_syscalls: int):
        input_dim = self._ngram_length * (self._extra_param + self._embedding_size)
        hidden_dim = 64
        n_layers = 1
        # output layer is #distinct_syscall + 1 for unknown syscalls
        self._lstm = Net(distinct_syscalls + 1,
                         input_dim,
                         hidden_dim,
                         n_layers)

    def train_on(self, feature_list: list):
        if self._lstm is None:
            x = np.array(feature_list[1:])
            y = feature_list[0][0]
            self._training_data['x'].append(x)
            self._training_data['y'].append(y)
        else:
            pass

    def fit(self):
        if self._lstm is None:
            x_tensors = Variable(torch.Tensor(self._training_data['x'])).to(self._device)
            y_tensors = Variable(torch.Tensor(self._training_data['y'])).to(self._device)
            y_tensors = y_tensors.long()
            x_tensors_final = torch.reshape(x_tensors, (x_tensors.shape[0], 1, x_tensors.shape[1]))
            print(f"Training Shape x: {x_tensors_final.shape} y: {y_tensors.shape}")
            self._set_model(self._distinct_syscalls)
            self._lstm.to(self._device)
            learning_rate = 0.001
            criterion = torch.nn.CrossEntropyLoss()
            optimizer = torch.optim.Adam(self._lstm.parameters(), lr=learning_rate)
            torch.manual_seed(1)
            for epoch in tqdm(range(self._epochs), 'training network:'.rjust(25), unit=" epochs"):
                outputs = self._lstm.forward(x_tensors_final)
                optimizer.zero_grad()  # caluclate the gradient, manually setting to 0

                # obtain the loss function
                loss = criterion(outputs, y_tensors)

                loss.backward()  # calculates the loss of the loss function

                optimizer.step()  # improve from loss, i.e backprop
                if epoch % 10 == 0:
                    self._accuracy(outputs, y_tensors)
                    print("Epoch: %d, loss: %1.5f" % (epoch, loss.item()))
            torch.save(self._lstm.state_dict(), self._model_path)
        else:
            pass

    def predict(self, feature_list: list) -> float:
        x_tensor = Variable(torch.Tensor(np.array([feature_list[1:]])))
        x_tensor_final = torch.reshape(x_tensor, (x_tensor.shape[0], 1, x_tensor.shape[1]))
        actual_syscall = feature_list[0][0]
        prediction_logits = self._lstm(x_tensor_final)
        softmax = nn.Softmax()
        prediction_probs = softmax(prediction_logits)
        predicted_probability = prediction_probs[0][actual_syscall]
        anomaly_score = 1 - predicted_probability
        return anomaly_score

    def _accuracy(self, outputs, y_tensors):
        hit = 0
        miss = 0
        for i in range(len(outputs)):
            pred = torch.argmax(outputs[i])
            if pred == y_tensors[i]:
                hit += 1
            else:
                miss += 1
        print(f"accuracy {hit/(hit+miss)}")


class Net(nn.Module):

    def __init__(self, num_classes, input_size, hidden_size, num_layers):
        super(Net, self).__init__()
        self.num_classes = num_classes
        self.num_layers = num_layers  # number of layers
        self.input_size = input_size  # input size
        self.hidden_size = hidden_size  # hidden state

        self.lstm = nn.LSTM(input_size=input_size, hidden_size=hidden_size,
                            num_layers=num_layers, batch_first=True)
        self.fc_1 = nn.Linear(hidden_size, 128)  # fully connected 1
        self.output = nn.Linear(hidden_size, num_classes)  # fully connected 1
        self.fc = nn.Linear(128, num_classes)  # fully connected last layer
        self.relu = nn.ReLU()
        self.tanh = nn.Tanh()
        self._device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")

    def forward(self, x):
        # hidden state
        h_0 = Variable(torch.zeros(self.num_layers, x.size(0), self.hidden_size)).to(self._device)
        # internal state
        c_0 = Variable(torch.zeros(self.num_layers, x.size(0), self.hidden_size)).to(self._device)
        # Propagate input through LSTM
        output, (hn, cn) = self.lstm(x, (h_0, c_0))  # lstm with input, hidden, and internal state
        hn = hn.view(-1, self.hidden_size)  # reshaping the data for Dense layer next
        out = self.tanh(hn)
        out = self.output(out)
        return out

from collections import deque

import syscall
from Tools.data_loader import DataLoader


class Stide:
    def __init__(self, ngram_length: int, window_length: int):

        self._ngram_length = ngram_length
        self._window_length = window_length
        self._syscall_dict = {}
        self._syscall_set_train = set([])
        self._q_train = deque(maxlen=ngram_length)

    def _get_int_from_syscall(self, syscall_name: str) -> int:

        if not syscall_name in self._syscall_dict:
            self._syscall_dict[syscall_name] = len(self._syscall_dicts) + 1
        return self._syscall_dict[syscall_name]


    def train_syscall(self, syscall: syscall.Syscall):

        self._q_train.append(self._get_int_from_syscall(syscall))
        if len(self._q_train) < self._ngram_length:
            return

        qtuple = tuple(self._q_train)

        if not qtuple in self._syscall_set_train:
            if len(qtuple == self._ngram_length):
                self._scall_set_train.append(qtuple)

        return(self._syscall_set_train)

    def calculate_threshold(self, syscall: syscall.Syscall):

        list_perc_unknown_ngrams = []
        ngram = deque(maxlen=self._ngram_length)
        sl_win = deque(maxlen=self._window_length)

        ngram.append(self._get_int_from_syscall(syscall))

        if len(ngram) == self._ngram_length:
            sl_win.append(tuple(ngram))

            if len(sl_win) == self._window_length:
                sc_occur_number = 0

                for tuple_sl_win in sl_win:
                    if tuple_sl_win not in self._syscall_set_trains:
                        sc_occur_number += 1

                list_perc_unknown_ngrams.append(sc_occur_number / self._window_length)

                return max(list_perc_unknown_ngrams)

    def detection(self, syscall: syscall.Syscall):
        list_perc_unknown_ngrams = []
        ngram = deque(maxlen=self._ngram_length)
        sl_win = deque(maxlen=self._window_length)

        ngram.append(self._get_int_from_syscall(syscall))

        if len(ngram) == self._ngram_length:
            sl_win.append(tuple(ngram))

            if len(sl_win) == self._window_length:
                sc_occur_number = 0

                for tuple_sl_win in sl_win:
                    if tuple_sl_win not in self._sc_set_train:
                        sc_occur_number += 1

                list_perc_unknown_ngrams.append(sc_occur_number / self._window_length)
                anomaly_score = max(list_perc_unknown_ngrams)
                return anomaly_score


def main():
    scenario_path = "/home/eschulze/LID-DS-2021 Datensatz/CVE-2017-7529"
    ngram_length = 3
    window_length = 50

    dataloader = DataLoader(scenario_path)

    stide = Stide(ngram_length, window_length)

    for recording in dataloader.dataloader_training_data():
        for syscall in recording.syscall():
            stide.train_syscall(syscall)
            stide.end_training()

    for recording in dataloader.validation_data():
        for syscall in recording.syscall():
            threshold = stide.calculate_threshold()


    for recording in dataloader.test_data():
        for syscall in recording.syscalls():

            anomaly_score = stide.calculate_threshold(syscall)
            if anomaly_score > threshold:
                print("alarm")

from collections import deque

import matplotlib
from tqdm import tqdm

from Tools.data_loader import DataLoader

import argparse

import matplotlib.pyplot as plt

matplotlib.use("TkAgg")


class Stide:
    def __init__(self, ngram_length: int, window_length: int):

        self._ngram_length = ngram_length
        self._window_length = window_length
        self._syscall_dict = {}
        self._trainingsset_ngrams = set()
        self._q_ngram = deque(maxlen=ngram_length)
        self._training_done = False
        self._list_perc_unknown_ngrams = []
        self._sl_win = deque(maxlen=self._window_length)
        self._mismatch_count_sl_win = 0
        self._qtuple = ()

    def _get_int_from_syscall(self, syscall) -> int:

        if not syscall.name() in self._syscall_dict:
            self._syscall_dict[syscall._name] = len(self._syscall_dict) + 1
        return self._syscall_dict[syscall._name]

    def clear_deques(self):
        self._q_ngram.clear()
        self._sl_win.clear()

    def consume_syscall(self, syscall):

        if self._training_done == False:

            self._q_ngram.append(self._get_int_from_syscall(syscall))

            if len(self._q_ngram) >= self._ngram_length:
                self._qtuple = tuple(self._q_ngram)
                # print(qtuple)

                if not self._qtuple in self._trainingsset_ngrams:
                    self._trainingsset_ngrams.add(self._qtuple)
                    # print(self._syscall_set_train)

        elif self._training_done == True:
            self._q_ngram.append(self._get_int_from_syscall(syscall))
            if len(self._q_ngram) >= self._ngram_length:
                self._qtuple = tuple(self._q_ngram)
                if len(self._sl_win) >= self._window_length:
                    self._mismatch_count_sl_win -= self._sl_win[0]
                mismatch = 0 if self._qtuple in self._trainingsset_ngrams else 1
                self._sl_win.append(mismatch)
                self._mismatch_count_sl_win += mismatch

                return (self._mismatch_count_sl_win / self._window_length)
        return 0


def main():
    # scenario_path = "//home/eschulze/LID-DS-2021 Datensatz/Bruteforce_CWE-307"
    # ngram_length = 7
    # window_length = 50

    parser = argparse.ArgumentParser()
    parser.add_argument('--path', action='store', type=str, required=True,
                        help='LID-DS Base Path')
    parser.add_argument('--ngram', action='store', type=int, required=True,
                        help='n-gram length')
    parser.add_argument('--window', action='store', type=int, required=True,
                        help='window length')
    args = parser.parse_args()

    dataloader = DataLoader(args.path)

    stide = Stide(args.ngram, args.window)

    for recording in tqdm(dataloader.training_data(), "training", unit=" recordings", smoothing=0):
        for syscall in recording.syscalls():
            stide.consume_syscall(syscall)
    stide._training_done = True
    stide.clear_deques()

    max = 0
    for recording in tqdm(dataloader.validation_data(), "calculating threshold", unit=" recordings", smoothing=0):
        for syscall in recording.syscalls():
            score = stide.consume_syscall(syscall)
            if score > max:
                max = score
    threshold = max
    print(f"threshold = {threshold}")
    stide.clear_deques()

    true_positives = 0
    false_positives = 0
    true_negatives = 0
    false_negatives = 0

    plot_anomaly_scores = []
    running_index = 0
    for recording in tqdm(dataloader.test_data(), "detection", unit=" recordings", smoothing=0):
        exploit = recording.metadata()["exploit"]
        if exploit is True:
            exploit_time = recording.metadata()["time"]["exploit"][0]["absolute"]
            # print(exploit_time)
            first_syscall_after_exploit = False

        for syscall in recording.syscalls():
            running_index += 1
            if exploit is True and first_syscall_after_exploit is False:
                tmp_ts = syscall.timestamp_unix_in_ns() / 1000000000
                if tmp_ts > exploit_time:
                    plt.axvline(running_index, 0, 1, c="tan")
                    first_syscall_after_exploit = True
            anomaly_score = stide.consume_syscall(syscall)
            plot_anomaly_scores.append(anomaly_score)
            if anomaly_score > threshold and exploit is False:
                false_positives += 1


            elif anomaly_score < threshold and exploit is False:
                true_negatives += 1


            # elif anomaly_score < threshold and exploit is True: &sc kleiner
            # false_negatives += 1

            elif anomaly_score > threshold and exploit is True and syscall.timestamp_unix_in_ns() > exploit_time:
                true_positives += 1

    precision = true_positives / (true_positives + false_positives)
    recall = true_positives / (true_positives + false_negatives)

    print(f"true positives = {true_positives}\n"
          f"false positives/false alarm = {false_positives}\n"
          f"precision = {precision}\n"
          f"recall = {recall}\n"
          f"f1 = {2 * (precision * recall / (precision + recall))}\n")

    plt.plot(plot_anomaly_scores)
    plt.axhline(threshold)
    plt.show()


if __name__ == '__main__':
    main()

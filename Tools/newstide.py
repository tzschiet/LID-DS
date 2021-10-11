from collections import deque

from tqdm import tqdm

from Tools.recording import Recording
from syscall import Syscall
from Tools.data_loader import DataLoader


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

    def _get_int_from_syscall(self, syscall) -> int:

        if not syscall.name() in self._syscall_dict:
            self._syscall_dict[syscall._name] = len(self._syscall_dict) + 1
        return self._syscall_dict[syscall._name]

    def clear_deques(self):
        self._q_ngram.clear()
        self._sl_win.clear()

    def consume_syscall(self,syscall):

        if self._training_done == False:

            self._q_ngram.append(self._get_int_from_syscall(syscall))

            if len(self._q_ngram) >= self._ngram_length:
                qtuple = tuple(self._q_ngram)
                #print(qtuple)

                if not qtuple in self._trainingsset_ngrams:
                    self._trainingsset_ngrams.add(qtuple)
                    #print(self._syscall_set_train)

        elif self._training_done == True:
            self._q_ngram.append(self._get_int_from_syscall(syscall))
            if len(self._q_ngram) >= self._ngram_length:
                self._sl_win.append(tuple(self._q_ngram))
                if len(self._sl_win) == self._window_length:
                    sc_occur_number = 0
                    for ngram_sl_win in self._sl_win:
                        if ngram_sl_win not in self._trainingsset_ngrams:
                            sc_occur_number += 1

                    return(sc_occur_number /self._window_length)
        return 0



def main():
    scenario_path = "/home/eschulze/LID-DS-2021 Datensatz/CVE-2017-7529"
    ngram_length = 3
    window_length = 50

    dataloader = DataLoader(scenario_path)

    stide = Stide(ngram_length, window_length)

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

    alarm_counter = 0
    false_alarm_counter = 0
    for recording in tqdm(dataloader.test_data(), "detection", unit=" recordings", smoothing=0):
        exploit = recording.metadata()["exploit"]
        for syscall in recording.syscalls():
            anomaly_score = stide.consume_syscall(syscall)
            if anomaly_score > threshold and exploit is False:
                false_alarm_counter += 1

            elif anomaly_score > threshold and exploit is True:
                alarm_counter = +1

    print(f"alarm_counter =  {alarm_counter}",
          f"false_alarm_counter =  {false_alarm_counter}")



if __name__ == '__main__':
    main()
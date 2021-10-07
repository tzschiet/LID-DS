from Tools.data_loader import DataLoader, RecordingType
from collections import deque



def main():

    scenario_path = "/home/eschulze/LID-DS-2021 Datensatz/CVE-2017-7529"
    ngram_length = 3
    window_length = 50

    dataloader = DataLoader(scenario_path)

    stide = Stide(ngram_length, window_length)

    syscall_dict ={}

    for recording in dataloader.dataloader_training_data():
        for syscall in recording.syscall():
            stide.get_syscall_int(syscall.name())
            anomaly_score = stide.consume_syscall(syscall)
            stide.end_training()

    for recording in dataloader.validation_data():
        for syscall in recording.syscall():
            stide.get_syscall_int(syscall.name())
            threshold = stide.calculate_threshold()

   for recording in dataloader.test_data():
        for syscall in recording.syscalls():
            stide.get_syscall_int(syscall.name())

            anomaly_score = stide.calculate_threshold(syscall)
            if anomaly_score > threshold:
                print("alarm")


class Stide:
    def __init__(self):

    syscall_dict ={}
    syscall_set_train = ([])
    q_train = deque(maxlen=ngram_length)

    def get_syscall_int(self, syscall_name):

        if not syscall_name in sc_dict:
            syscall_dict[syscall] = len(syscall_dict) + 1
        return syscall_int = syscall_dict[syscall]


    def consume_syscall(self, syscall_int):

        q_train.append(get_syscall_int())

        qtuple = tuple(q_train)

        if not qtuple in syscall_set_train:
            if len(qtuple == ngram_length):
                syscall_set_train.append(qtuple)

    def calculate_threshold(self):

        list_perc_unknown_ngrams =  []
        ngram = deque(maxlen=ngram_length)
        sl_win = deque(maxlen=window_length)

        ngram.append(sc_dict[systemcall.name()])

        if len(ngram) == ngram_length:
            sl_win.append(tuple(ngram))

            if len(sl_win) == window_length:
                sc_occur_number = 0

                for tuple_sl_win in sl_win:
                    if tuple_sl_win not in sc_set_train:
                        sc_occur_number += 1

                list_perc_unknown_ngrams.append(sc_occur_number / window_length)

                return max(list_perc_unknown_ngrams)

    def detection(self):
        list_perc_unknown_ngrams = []
        ngram = deque(maxlen=ngram_length)
        sl_win = deque(maxlen=window_length)

        ngram.append(sc_dict[systemcall.name()])

        if len(ngram) == ngram_length:
            sl_win.append(tuple(ngram))

            if len(sl_win) == window_length:
                sc_occur_number = 0

                for tuple_sl_win in sl_win:
                    if tuple_sl_win not in sc_set_train:
                        sc_occur_number += 1

                list_perc_unknown_ngrams.append(sc_occur_number / window_length)
                anomaly_score = max(list_perc_unknown_ngrams)
                return anomaly_score

def end_training(self):



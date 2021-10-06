from Tools.data_loader import DataLoader, RecordingType
from collections import deque

ngram_length = 3
window_length = 50

sc_dict = {}
sc_set_train = ([])
q_train = deque(maxlen=ngram_length)


def get_sc_number(syscall):
    if not syscall in sc_dict:
        sc_dict[syscall] = len(sc_dict) + 1
    return sc_dict[syscall]


dataloader = DataLoader("/home/eschulze/LID-DS-2021 Datensatz/CVE-2017-7529")
for recording in dataloader.training_data():
    #print(recording.name)
    for systemcall in recording.syscalls():

        q_train.append(get_sc_number(systemcall.name()))

        qtuple = tuple(q_train)

        if not qtuple in sc_set_train:
            if len(qtuple) == ngram_length:
                sc_set_train.append(qtuple)


def get_threshold():
    list_perc_unknown_ngrams = []
    for recording in dataloader.validation_data():

        ngram = deque(maxlen=ngram_length)
        sl_win = deque(maxlen=window_length)

        for systemcall in recording.syscalls():

            ngram.append(sc_dict[systemcall.name()])

            if len(ngram) == ngram_length:
                sl_win.append(tuple(ngram))

                if len(sl_win) == window_length:
                    sc_occur_number = 0

                    for tuple_sl_win in sl_win:
                        if tuple_sl_win not in sc_set_train:
                            sc_occur_number += 1



                    list_perc_unknown_ngrams.append(sc_occur_number / window_length)



    return (max(list_perc_unknown_ngrams))

print(get_threshold())

















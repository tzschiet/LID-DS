from Tools.data_loader import DataLoader, RecordingType
from collections import deque

q = deque(maxlen=3)
sc_dict_int = {}
sc_dict_count = {}

dataloader = DataLoader("/home/eschulze/LID-DS-2021 Datensatz/CVE-2012-2122")
for recording in dataloader.test_data():
    print(recording.name)
    for systemcall in recording.syscalls():

        if not str(systemcall.name()) in sc_dict_int:
            sc_dict_int[str(systemcall.name())] = len(sc_dict_int) + 1

        q.append(sc_dict_int[str(systemcall.name())])

        qtuple = tuple(q)

        if len(qtuple) == 3:
            if not qtuple in sc_dict_count:
                sc_dict_count[qtuple] = 1

            else:
                sc_dict_count[qtuple] += 1

print(sc_dict_count)

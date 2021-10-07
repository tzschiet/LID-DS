from Tools.data_loader import DataLoader, RecordingType
from collections import deque

n = 3

q = deque(maxlen=n)
sc_dict = {}
sc_dict_count = {}

dataloader = DataLoader("/home/eschulze/LID-DS-2021 Datensatz/CVE-2017-7529")
for recording in dataloader.test_data():
    print(recording.name)
    for systemcall in recording.syscalls():

        if not systemcall.name() in sc_dict:
            sc_dict[systemcall.name()] = len(sc_dict) + 1

        q.append(sc_dict[systemcall.name()])

        qtuple = tuple(q)

        if not qtuple in sc_dict_count:
            sc_dict_count[qtuple] = 1

        else:
            sc_dict_count[qtuple] += 1

print(sc_dict_count)

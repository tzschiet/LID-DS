from Tools.data_loader import DataLoader, RecordingType



dataloader = DataLoader("/home/eschulze/LID-DS-2021 Datensatz/CVE-2012-2122")
for recording in dataloader.test_data():
    print(recording.name)
    for systemcall in recording.syscalls():
        print(systemcall.name())
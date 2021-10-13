import fe_stide
import stream_fe_stide
import decision_engine_stide
from tqdm import tqdm


from Tools.data_loader import DataLoader
import argparse

def main ():

    """parser = argparse.ArgumentParser()
    parser.add_argument('--path', action='store', type=str, required=True,
                        help='LID-DS Base Path')
    parser.add_argument('--ngram', action='store', type=int, required=True,
                        help='n-gram length')
    parser.add_argument('--window', action='store', type=int, required=True,
                        help='window length')
    args = parser.parse_args()"""

    scenario_path = "//home/eschulze/LID-DS-2021 Datensatz/Bruteforce_CWE-307"
    ngram_length = 7
    window_length = 50

    dataloader = DataLoader(scenario_path)

    stide = decision_engine_stide.Stide(ngram_length, window_length)

    for recording in tqdm(dataloader.training_data(), "training", unit=" recordings", smoothing=0):
        for syscall in recording.syscalls():
            fe_stide.feature_extractor_stide.extract(syscall)

    for recording in tqdm(dataloader.validation_data(), "validation", unit=" recordings", smoothing=0):
        for syscall in recording.syscalls():
            fe_stide.feature_extractor_stide.extract(syscall)

    for recording in tqdm(dataloader.test_data(), "detection", unit=" recordings", smoothing=0):
        for syscall in recording.syscalls():
            fe_stide.feature_extractor_stide.extract(syscall)




if __name__ == "__main__":
    main()
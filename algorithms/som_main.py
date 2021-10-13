from datetime import timedelta

from tqdm import tqdm

from algorithms.word_embedding import WordEmbedding
from algorithms.threadID_extractor import ThreadIDExtractor
from algorithms.stream_ngram_extractor import StreamNgramExtractor
from algorithms.som_decision_engine import SomDecisionEngine

from dataloader.data_loader_2019 import DataLoader

from dataloader.syscall import Syscall


def collect_features(syscall: Syscall,
                     feature_extractors: list) -> dict:
    feature_dict = {}
    for feature in feature_extractors:
        k, v = feature.extract(syscall)
        feature_dict[k] = v
    return feature_dict


def collect_stream_features(feature_dict: dict,
                            stream_feature_extractors: list) -> list:
    stream_feature_dict = {}
    for sfe in stream_feature_extractors:
        k, v = sfe.extract(feature_dict)
        if v is not None:
            stream_feature_dict[k] = v
    extracted_feature_list = []
    for key in stream_feature_dict.keys():
        extracted_feature_list += stream_feature_dict[key]
    return extracted_feature_list


if __name__ == '__main__':
    """

        combination of:
            feature_extractor
            stream_feature_extractor
            decision_engine

    """

    w2v_extractor = WordEmbedding(window=5,
                                  vector_size=5,
                                  thread_aware=True)
    tid_extractor = ThreadIDExtractor()

    FE = [w2v_extractor, tid_extractor]

    ngram_extractor = StreamNgramExtractor(feature_list=['w2v'],
                                           thread_aware=True,
                                           ngram_length=7)
    SFE = [ngram_extractor]

    som_de = SomDecisionEngine(epochs=50)

    # prepare example scenario
    data_loader = DataLoader('/home/felix/repos/LID-DS/LID-DS-2019/CVE-2017-7529')

    # train FEs
    training_data = data_loader.training_data()
    for recording in training_data:
        for syscall in recording.syscalls():
            for fe in FE:
                fe.train_on(syscall)

    # fit FEs
    for fe in FE:
        fe.fit()

    # train SFEs
    training_data = data_loader.training_data()
    for recording in training_data:
        for syscall in recording.syscalls():
            feature_dict = collect_features(syscall, FE)
            for sfe in SFE:
                sfe.train_on(feature_dict)

    # fit SFEs
    for sfe in SFE:
        sfe.fit()
    # train of DE
    for recording in training_data:
        for syscall in recording.syscalls():
            # preprocessing
            feature_dict = collect_features(syscall, FE)
            stream_feature_list = collect_stream_features(feature_dict, SFE)
            if len(stream_feature_list) > 0:
                som_de.train_on(stream_feature_list)

    som_de.fit()
    # som_de.show_distance_plot()


    # calculating threshold
    threshold = 0
    for recording in tqdm(data_loader.validation_data(), desc='Finding Threshold'):
        for syscall in recording.syscalls():
            feature_dict = collect_features(syscall, FE)
            stream_feature_list = collect_stream_features(feature_dict, SFE)

            if len(stream_feature_list) > 0:
                distance = som_de.predict(stream_feature_list)

                if distance > threshold:
                    threshold = distance

    print(threshold)

    # detection
    result_dict = {
        'TP': 0,
        'TN': 0,
        'FP': 0
    }

    for recording in tqdm(data_loader.test_data()):
        exploit_time = 0
        metadata = recording.metadata()

        is_exploited = metadata['exploit']
        if is_exploited:
            relative_exploit_start = metadata['time']['exploit'][0]['relative']
        
        for syscall in recording.syscalls():
            if exploit_time == 0:
                first_timestamp = syscall.timestamp_datetime()
                if is_exploited:
                    exploit_time = first_timestamp + timedelta(seconds=relative_exploit_start)

            feature_dict = collect_features(syscall, FE)
            stream_feature_list = collect_stream_features(feature_dict, SFE)

            if len(stream_feature_list) > 0:
                distance = som_de.predict(stream_feature_list)

                syscall_timestamp = syscall.timestamp_datetime()

                # positive
                if distance > threshold:
                    if is_exploited:
                        if syscall_timestamp > exploit_time:
                            result_dict['TP'] += 1
                        else:
                            result_dict['FP'] += 1
                    else:
                        result_dict['FP'] += 1
                # negative
                else:
                    if is_exploited:
                        if syscall_timestamp < exploit_time:
                            result_dict['TN'] += 1
                    else:
                        result_dict['TN'] += 1

    print(result_dict)








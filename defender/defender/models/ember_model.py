from ember import PEFeatureExtractor
import lightgbm as lgb
import numpy as np
import gzip
from annoy import AnnoyIndex  # pip install --user annoy
from random import randint
import lief
import logging

logging.basicConfig(level=logging.DEBUG)
EMBER_MODEL_PATH = 'defender/models/ember_model.txt.gz'


class EmberModel(object):
    '''Implements predict(self, bytez)'''
    def __init__(self,
                 model_gz_path: str = EMBER_MODEL_PATH,
                 thresh: float = 0.8336,  # resulting in 1% FPR
                 name: str = 'ember'):
        # load lightgbm model
        with gzip.open(model_gz_path, 'rb') as f:
            model = f.read().decode('ascii')

        self.model_gz_path = model_gz_path
        self.model = lgb.Booster(model_str=model)
        self.thresh = thresh
        self.__name__ = name
        self.extractor = PEFeatureExtractor(2)  # feature_version=2

    def predict(self, bytez: bytes) -> int:
        score = self.predict_proba(bytez)
        return int(score > self.thresh)

    def predict_proba(self, bytez: bytes) -> float:
        self.features = np.array(self.extractor.feature_vector(bytez),
                                 dtype=np.float32)
        return self.model.predict([self.features])[0]

    def model_info(self) -> dict:
        return {"model_gz_path": self.model_gz_path,
                "thresh": self.thresh,
                "name": self.__name__}


class TrimPEFile(object):
    '''Trim a PE file from excessive sections, imports, overlay.  This removes content and
    most likely breaks the PE file format.  But, this doesn't matter to a defender.'''
    def __init__(self,
                 max_sections: int = 5,
                 max_section_size: int = 2**16,  # 64k
                 max_overlay: int = 128,
                 ):
        self.max_sections = max_sections
        self.max_section_size = max_section_size
        self.max_overlay = max_overlay

    def trim(self, bytez: bytes) -> bytes:
        # this operation may break the input file, but as a defender, we don't care
        try:
            pe = lief.parse(raw=bytez)
        except lief.read_out_of_bound:
            return bytez

        if not pe:
            return bytez

        # start assembling a new PE file
        new = lief.PE.Binary(pe.name, pe.optional_header.magic)  # preserve PE32 or PE32+ (64-bit) status

        # copy over the first several sections
        for i, s in enumerate(pe.sections):

            if i >= self.max_sections:
                break

            if s.name.lower() == '.text':          #
                typ = lief.PE.SECTION_TYPES.TEXT
            elif s.name.lower() == '.data' or s.name.lower() == '.rdata':
                typ = lief.PE.SECTION_TYPES.DATA
            elif s.name.lower() == '.idata':        # import section
                typ = lief.PE.SECTION_TYPES.IDATA
            elif s.name.lower() == '.edata':        # export section
                typ = lief.PE.SECTION_TYPES.EXPORT
            elif s.name.lower() == '.bss':          # uninitialized data
                typ = lief.PE.SECTION_TYPES.BSS
            elif s.name.lower() == '.rsrc':         # resources section
                typ = lief.PE.SECTION_TYPES.RESOURCE
            elif s.name.lower() == '.reloc':
                typ = lief.PE.SECTION_TYPES.RELOCATION
            elif s.name.lower() == '.tls':
                typ = lief.PE.SECTION_TYPES.TLS_
            else:
                typ = lief.PE.SECTION_TYPES.UNKNOWN
            s.content = s.content[:self.max_section_size]
            s.size = len(s.content)
            new.add_section(s, typ)

        # build the new PE file
        builder = lief.PE.Builder(new)
        builder.build()

        newbytez = builder.get_build()

        if len(newbytez) == 0:
            return bytez  # failed

        # copy over truncated overlay
        overlay = pe.overlay
        newbytez += overlay[:self.max_overlay]

        return bytes(newbytez)


class StatefulNNEmberModel(EmberModel):
    '''Adds stateful nearest-neighbor detection of adversarial examples to base ember model.
    If a sample (or a trimmed variant) is deemed benign by EMBER, first check history of queries
    for a sufficiently close malicious neighbor, and outputs "malicious" if one is found. Else, benign.

    Note that during the competition, the organizers will submit benign samples to the models, so care must be taken
    so that the stateful history doesn't include any benign samples that could result in a high FP rate.
    '''
    ADV_INDEX_SIZE = 512  # grab the first ADV_INDEX_SIZE features, corresponding to histogram(256) and byteentropy(256)
    # features are described by self.extractor.features:
    #   [histogram(256), byteentropy(256), strings(104), general(10),
    #    header(62), section(255), imports(1280), exports(128), datadirectories(30)]

    def __init__(self,
                 model_gz_path: str = EMBER_MODEL_PATH,
                 thresh: float = 0.8336,     # resulting in 1% FPR
                 ball_thresh: float = 0.25,   # threshold for L1 distance to previously-seen malware
                 max_history: int = 10_000,  # keep up to this much query history
                 name: str = 'defended-ember'):
        super().__init__(model_gz_path, thresh, name)
        self.malicious_queries = []
        self.max_history = max_history
        self.ball_thresh = ball_thresh
        self.trimmer = TrimPEFile()

    def predict(self, bytez: bytes) -> int:
        score = self.predict_proba(bytez)
        trimmed_bytez = self.trimmer.trim(bytez)
        trimmed_score = self.predict_proba(trimmed_bytez)
        trimmed_features = self.features

        # after predict_proba, self.features contains feature vector for bytez
        # features are described by self.extractor.features:
        #   [histogram(256), byteentropy(256), strings(104), general(10),
        #    header(62), section(255), imports(1280), exports(128), datadirectories(30)]
        # we'll use only the first 2 categories (512 columns) to index samples.

        if score > self.thresh or trimmed_score > self.thresh:
            self.malicious_queries.append((trimmed_features[:self.ADV_INDEX_SIZE], score))
            # if the list is too big, shuffle and trim (keep a random subset)
            while len(self.malicious_queries) > self.max_history:
                # remove a random element
                self.malicious_queries.pop(index=randint(0, len(self.malicious_queries)))

        elif len(self.malicious_queries) > 0:
            # is it sufficiently similar to some malicious sample I've seen previously?
            t = AnnoyIndex(self.ADV_INDEX_SIZE, 'manhattan')
            for i, (m, _) in enumerate(self.malicious_queries):
                t.add_item(i, m)
            t.build(20)

            # is the core of the is file similar to a malicious file I've seen?
            q = trimmed_features[:self.ADV_INDEX_SIZE]
            nn_ix = t.get_nns_by_vector(q, 10)

            dists = [np.linalg.norm(self.malicious_queries[ix][0] - q, 1) for ix in nn_ix]
            min_dist = min(dists)  # how close is the actual nearest neighbor?

            if min_dist < self.ball_thresh:
                logging.info("Detected Adversarial Example!")
                score = 1

        # else
        result = int(score > self.thresh)
        logging.info(f'result: {result}')
        return result


if __name__ == '__main__':
    # to run this file, from the defender folder, run
    # python -m defender.models.ember_model

    # let's determine a threshold for StatefulNNEmberModel.ball_thresh
    # Do this by comparing NN distance of (2019 evasive variant, base malware sample) pairs 
    # to the distance of (benign malware samples, base malware sample) pairs, across a large set of benign malware samples
    #
    # In what follows, I've assembled the samples in MLSEC_2019_samples_and_variants.zip into
    # two separate archives:
    #  /tmp/MLSEC_samples.zip  contains the 2019 base malware samples
    #  /tmp/*.zip              each zip file contains 2019 evasive variants for a single user batch submission, with entries matching the base malware name
    # For benign samples, I'm using a C:\Windows\System32 (Windows 10), which is mounted automatically via WSL2 (https://docs.microsoft.com/en-us/windows/wsl/install-win10) under
    #  /mnt/c/windows/system32

    from test import file_bytes_generator
    import glob
    from collections import defaultdict
    import os

    fe = PEFeatureExtractor(2)
    ADV_INDEX_SIZE = 512  # grab the first ADV_INDEX_SIZE features, corresponding to histogram(256) and byteentropy(256)
    # features are described by self.extractor.features:
    #   [histogram(256), byteentropy(256), strings(104), general(10),
    #    header(62), section(255), imports(1280), exports(128), datadirectories(30)]

    trimmer = TrimPEFile()

    print('examining base malware samples...')
    samples = []
    sample_names = []
    for name, bytez in file_bytes_generator('/tmp/MLSEC_samples.zip', maxsize=2**21):
        print(name)
        fv = fe.feature_vector(trimmer.trim(bytez))
        samples.append(fv[:ADV_INDEX_SIZE])
        sample_names.append(os.path.basename(name))

    samples = np.array(samples)

    print('examining novel malware variants...')
    malware_dist = defaultdict(list)
    for z in glob.glob('/tmp/submissions/*.zip'):
        print(z)
        for name, bytez in file_bytes_generator(z, maxsize=2**21):
            print(name)
            basename = os.path.basename(name)
            m_idx = sample_names.index(basename)
            fv = fe.feature_vector(trimmer.trim(bytez))
            q = np.array(fv[:ADV_INDEX_SIZE])
            normalized_dist = np.sum(np.abs(samples[m_idx, :] - q))  # distance of evasive variant to original
            malware_dist[basename].append((name, normalized_dist))

    print('examining benign samples...')
    benign_dist = defaultdict(list)
    for i, (name, bytez) in enumerate(file_bytes_generator('/mnt/c/windows/system32/', maxsize=2**21)):
        if i > 1000:
            break
        print(name)
        fv = fe.feature_vector(trimmer.trim(bytez))
        q = np.array(fv[:ADV_INDEX_SIZE])
        normalized_dist = np.sum(np.abs(samples - q), axis=1)  # distance from benign to every base malware sample
        for d, n in zip(normalized_dist, sample_names):
            benign_dist[n].append((name, d))

    # compute distance percentiles from benign/evasive samples to base malware samples
    malware_stats = np.percentile([vv[1] for k, v in malware_dist.items() for vv in v], [10.0, 50.0, 90.0])
    benign_stats = np.percentile([vv[1] for k, v in benign_dist.items() for vv in v], [0.1, 0.5, 1.0])

    print('distance percentiles for evasive variants (10%, 50%, 90%):')
    print(malware_stats)
    print('distance percentiles for benign samples (0.1%, 0.5%, 1%):')
    print(benign_stats)

    # distance percentiles for evasive variants (10%, 50%, 90%):
    # [2.92558077e-04 1.41343959e-02 2.23442249e+00]
    # distance percentiles for benign samples (0.1%, 0.5%, 1%):
    # [0.291772   0.40277199 0.49259179]

    # I'll set the StatefulNNEmberModel.ball_thresh = 0.25
    # The decision is based purely on low FP rate, to prevent the stateful protection from drifting into a state
    # wherein it labels EVERYTHING as an adversarial example.  This threshold should also catch a large fraction
    # of the 2019 evasive variants, prodived that the stateful detection model first observes the base malware sample.

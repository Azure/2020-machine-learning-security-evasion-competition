import glob
import lief
from collections import defaultdict, Counter
import numpy as np
from hyperopt import hp, pyll, fmin, tpe, Trials, STATUS_OK, STATUS_FAIL
import pickle
from attacker.attacker.utils.modify import PEFileModifier
from attacker.attacker.clientbase import BlackBoxOfflineClient, BlackBoxOnlineClient
from defender.defender.models.ember_model import EmberModel
import logging

MAXFILESIZE = 2**21


class EmberGuidedBlackBox(object):
    def __init__(self, api_token, model_gz_path, online=False):
        self.api_token = api_token
        self.online(online)
        self.ember = EmberModel(model_gz_path)

    def online(self, online=False):
        self.is_online = online
        if online:
            self.model = BlackBoxOnlineClient(self.api_token)
        else:
            self.model = BlackBoxOfflineClient()

    def predict_models(self, bytez):
        # get score from local ember model
        try:
            score = self.ember.predict_proba(bytez)
        except Exception as e:
            logging.warning(e)
            score = 1.0

        # get predictions from online/offline model(s)
        predictions = self.model.predict(bytez)

        all_predictions = predictions + [score]

        return all_predictions


class HyperOptAttacker(object):
    ''' uses hyperopt's Tree Parzen Estimator (TPE) for black-box optimization
    of a parameter space that consists of function-preserving file modifications '''

    def __init__(self, classifier, benign_folder):
        assert hasattr(classifier, 'predict_models'), 'expecting "classifier" to have a predict_models method'
        self.classifier = classifier

        # initialize from files
        self.initialize_benign_content(benign_folder)

        # initialize optimization space
        MAX_SECTIONS = 20
        MAX_LIBRARIES = 20
        section_opts = {f's{s}': hp.choice(f's{s}', [None, {'idx': hp.randint(f's_idx_{s}', len(self.sections)),
                                                            'pct': hp.uniform(f's_pct_{s}', 0, 1)}])
                        for s in range(MAX_SECTIONS)}

        import_opts = {f'i{s}': hp.choice(f'i{s}', [None, {'idx': hp.randint(f'i_idx_{s}', len(self.imports)),
                                                           'pct': hp.uniform(f'i_pct_{s}', 0, 1)}])
                       for s in range(MAX_LIBRARIES)}

        overlay_opts = hp.choice('overlay_info', [None, {'idx': hp.randint('o_idx', len(self.overlays)),
                                                         'pct': hp.uniform('o_pct', 0, 1)}])

        self.space = {
            'section_info': section_opts,
            'import_info': import_opts,
            'overlay_info': overlay_opts,
            'modify_timestamp': hp.choice('modify_timestamp', [None, {'pct': hp.uniform('t_pct', 0, 1)}]),
            'upx_unpack': hp.choice('upx_unpack', [False, True])
        }

    def initialize_benign_content(self, benign_folder):
        sections = []
        overlays = []
        imports = defaultdict(set)
        timestamps = []

        for fn in glob.glob(f'{benign_folder}/*'):
            print(fn)
            pe = lief.parse(fn)
            if not pe:
                continue
            for s in pe.sections:
                sections.append((s.name, s.characteristics, bytes(s.content)))
            for i in pe.imports:
                for f in i.entries:
                    imports[i.name].add(f.name)
            timestamps.append(pe.header.time_date_stamps)
            overlays.append(bytes(pe.overlay))

        imports = [(k, list(v)) for k, v in imports.items()]

        # let's sort by content length
        sections.sort(key=lambda x: len(x[2]), reverse=True)
        overlays.sort(key=lambda x: len(x), reverse=True)
        imports.sort(key=lambda x: len(x[1]), reverse=True)
        timestamps = [min(timestamps), max(timestamps)]

        # let's filter sections
        from collections import Counter

        def updatecounter(k, counter):
            counter.update([k])
            return counter[k]

        scounter = Counter()
        sections = [s for s in sections if updatecounter(f'{s[0]}{s[1]}', scounter) <= 2]  # how many of each name/characteristics?
        overlays = [o for o in overlays if len(o) >= 1024]
        imports = [i for i in imports if len(i[1]) >= 5]

        self.timestamps = timestamps
        self.sections = sections
        self.overlays = overlays
        self.imports = imports

    def attack(self, bytez, max_evals=250, threshold=0.5, history=None):
        if history is None:
            history = {'trials': Trials(), 'evals': 0}

        assert 'trials' in history and 'evals' in history, f'expecting "trials" and "evals" in "history" dict'

        def modify(bytez, space):
            # using global bytez
            modpe = PEFileModifier(bytez)

            # upx packing comes first
            if space['upx_unpack']:
                modpe.upx_unpack()

            # add some sections
            for _, v in space['section_info'].items():
                if v:
                    name, char, cont = self.sections[v['idx']]
                    _end = int(v['pct'] * len(cont))
                    modpe.add_section(name, char, cont[:_end])

            # add some imports
            for _, v in space['import_info'].items():
                if v:
                    lib, funcs = self.imports[v['idx']]
                    _end = int(v['pct'] * len(funcs))
                    modpe.add_imports(lib, funcs[:_end])

            # add to the overlay
            if space['overlay_info']:
                v = space['overlay_info']
                cont = self.overlays[v['idx']]
                _end = int(v['pct'] * len(cont))
                modpe.append_overlay(cont[:_end])

            # modify timestamp
            if space['modify_timestamp']:
                pct = space['modify_timestamp']['pct']
                t = int((1 - pct) * self.timestamps[0] + pct * self.timestamps[1])
                modpe.set_timestamp(t)

            # score the function...first check limits
            return modpe.content

        # define function to optimize
        def f(space):
            new_bytez = modify(bytez, space)

            if len(new_bytez) > MAXFILESIZE:
                return {
                    "loss": len(new_bytez) / MAXFILESIZE,  # a number larger than 1
                    "status": STATUS_FAIL,
                    "space": space
                }

            predictions = list(self.classifier.predict_models(new_bytez))

            return {
                "loss": float(np.mean(predictions)),
                "pred": predictions,
                "status": STATUS_OK,
                "space": space
            }

        # minimize the function
        fmin(
            fn=f,
            space=self.space,
            algo=tpe.suggest,
            trials=history['trials'],
            max_evals=history['evals'] + max_evals,
            loss_threshold=threshold,  # terminate early if the loss drops below this value
        )

        # how many iterations were actually taken?
        history['evals'] = len(history['trials'])

        # did we actually result in evasion?
        preds = history['trials'].best_trial['result']['pred']

        space = history['trials'].best_trial['result']['space']
        # generate the file from the space
        newbytez = modify(bytez, space)

        # return vector of predictions and the modified file that made them so
        return preds, newbytez, history

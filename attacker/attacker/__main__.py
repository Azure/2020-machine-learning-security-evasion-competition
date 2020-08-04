import click
import requests
import sys
# import toml
import os
from defender.test import file_bytes_generator, MAXFILESIZE
from .attacker import EmberGuidedBlackBox, HyperOptAttacker
import pickle
import logging

logging.basicConfig(level=logging.WARNING)
loggers_to_silence = [
    "hyperopt.tpe",
    "hyperopt.fmin",
    "hyperopt.pyll.base",
    "urllib3.connectionpool",
]
for logger in loggers_to_silence:
    logging.getLogger(logger).setLevel(logging.ERROR)

attack = None
model = None


@click.group()
def cli():
    pass


@click.command()
@click.option('--benign', required=True, type=str, help='folder containing benign samples')
@click.option('--api_token', required=True, type=str, help='api token')
@click.option('-o', required=True, type=str, help='output pickle file containing configuration data')
def init(benign, api_token, o):
    global attack
    global model
    model = EmberGuidedBlackBox(api_token=api_token, model_gz_path='defender/defender/models/ember_model.txt.gz')
    attack = HyperOptAttacker(model, benign)
    with open(o, 'wb') as outfile:
        pickle.dump({'model': model, 'attack': attack}, outfile)


@click.command()
@click.option('--config', required=True, type=str, help='path of config file (python pickle file) created in init step')
@click.option('--samples', required=True, type=str, help='folder or file containing malicious samples')
@click.option('--success_out', required=True, type=str, help='folder to store evasive variants the bypass the models (will create if necessary)')
@click.option('--failure_out', required=True, type=str, help='folder to store samples that only partiall bypass the models (will create if necessary)')
@click.option('--max-evals', type=int, help='maximum queries to allow', default=250)
@click.option('--local-server', type=str, help='URL for local black-box server to attack', default='http://127.0.0.1:8080/')
@click.option('--online', is_flag=True, default=False, help='attack local or online model')
def run(config, samples, success_out, failure_out, max_evals, local_server, online):
    global attack
    global model
    with open(config, 'rb') as infile:
        dat = pickle.load(infile)
        model = dat['model']
        attack = dat['attack']
    print(f'read config from {config}')

    model.online(online)  # set online or offline

    model_names = model.model.models if online else ['local']

    threshold = 1.0 / (len(model_names) + 1)  # quit if all blackbox models report label=0

    # create output folder if necessary
    os.makedirs(success_out, exist_ok=True)
    os.makedirs(failure_out, exist_ok=True)

    for fn, bytez in file_bytes_generator(samples, MAXFILESIZE):
        print(fn)
        # attempt to restory any history associated with this file
        history_fn = fn + '.history.pkl'
        if os.path.exists(history_fn):  # won't work with original ZIP file
            with open(history_fn, 'rb') as infile:
                history = pickle.load(infile)
        else:
            history = None

        preds, newbytez, history = attack.attack(bytez, max_evals=max_evals, history=history, threshold=threshold)
        # preds contains [model1, model2, ..., local_ember], where the last is our local heuristic
        # newbytez contains a sample with the best-scoring modifications implemented

        bypassed = [p == 0 for p in preds[:-1]]
        history['bypassed'] = dict(zip(model_names, bypassed))

        outfname = os.path.join(success_out if all(bypassed) else failure_out, os.path.basename(fn))
        out_history_fn = outfname + '.history.pkl'

        # write best candidate file
        with open(outfname, 'wb') as outfile:
            outfile.write(newbytez if all(bypassed) else bytez)  # if failed, write the original samples

        # write history, for possible re-use
        with open(out_history_fn, 'wb') as outfile:
            pickle.dump(history, outfile)


cli.add_command(init)
cli.add_command(run)

if __name__ == '__main__':
    cli()
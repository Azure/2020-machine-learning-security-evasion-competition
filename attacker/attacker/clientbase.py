import argparse
import requests
import sys
import time
import json


MLSEC_SUBMIT_API = 'https://api.mlsec.io/api/ml_submit_sample?api_token={api_token}&model={model}'  # POST
MLSEC_RETRIEVE_API = 'https://api.mlsec.io/api/ml_get_sample?api_token={api_token}&jobid={jobid}'  # GET
ALL_MODELS = ['ember', 'needforspeed', 'domumpqb']
SLEEP_DURATION = 1000


class BlackBoxOfflineClient(object):
    def __init__(self, url='http://127.0.0.1:8080'):
        self.url = url

    def predict(self, bytez):
        resp = requests.post(self.url, data=bytez, headers={'Content-Type': 'application/octet-stream'})
        json = resp.json()
        return [json['result']]


class BlackBoxOnlineClient(object):
    def __init__(self, api_token, models=ALL_MODELS, post_url=MLSEC_SUBMIT_API, get_url=MLSEC_RETRIEVE_API):
        self.api_token = api_token
        self.post_url = post_url
        self.get_url = get_url
        self.models = models

    def predict(self, bytez, models=None, wait_for=SLEEP_DURATION):
        if models is None:
            models = self.models
        for m in models:
            assert m in ALL_MODELS, f"invalid model {m} specified"

        mstr = ",".join(models)
        resp = requests.post(self.post_url.format(api_token=self.api_token, model=mstr),
                             data=bytez,
                             headers={'Content-Type': 'application/octet-stream'})
        assert resp.ok, f'POST error {resp.status_code}: {resp.text}'

        # retrieve jobid
        try:
            r = resp.json()
            jobid = r['jobid']
        except (json.JSONDecodeError, KeyError) as e:
            raise(e)

        # retry if not ready
        while True:
            resp = requests.get(self.get_url.format(api_token=self.api_token, jobid=jobid))
            if resp.status_code != 202:
                break
            time.sleep(wait_for)

        assert resp.ok, f'GET error {resp.status_code}: {resp.text}'
        r = resp.json()
        return [r[m]['result'] for m in models]  # return list of respones for queried models


if __name__ == '__main__':
    # first, start a docker image using
    # docker run -itp 8080:8080 ember

    model = BlackBoxOfflineClient()
    from defender.test import TINYIMPORT
    print(model.predict(TINYIMPORT))

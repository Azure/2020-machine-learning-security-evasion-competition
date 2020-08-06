# REST API
<!-- vscode-markdown-toc -->
* [Query Hosted ML models](#query-hosted-ml-models)
* [Upload ZIP files and check on status](#upload-zip-files-and-check-on-status)

<!-- vscode-markdown-toc-config
	numbering=false
	autoSave=true
	/vscode-markdown-toc-config -->
<!-- /vscode-markdown-toc -->

## <a name='query-hosted-ml-models'></a>Query Hosted ML models
Submit a sample to all hosted ML models, and retrieve a `jobid`
* [ml_submit_sample_all](ml_submit_sample_all.md): `POST https://api.mlsec.io/api/ml_submit_sample_all?api_token={api_token}`

Submit a sample to one or more specific ML models, and retrieve a `jobid`
* [ml_submit_sample](ml_submit_sample.md): `POST https://api.mlsec.io/api/ml_submit_sample?api_token={api_token}?model={model1,model2}`

Retrieve resuts from sample submission, referenced by `jobid`
* [ml_get_sample](ml_get_sample.md): `GET https://api.mlsec.io/api/ml_get_sample?api_token={api_token}&jobid={jobid}`

## <a name='upload-zip-files-and-check-on-status'></a>Upload ZIP files and check on status
**Rather than using these API routes, you may submit and view the status of your submission at [https://mlsec.io/zipfile](https://mlsec.io/zipfile/).**

Upload a ZIP file containing samples
* [post_one_zip](post_one_zip.md): `POST https://api.mlsec.io/api/post_one_zip/new/?url=%2Fzipfile%2F&api_token={api_token}`

Query specific ZIP status
* [get_one_zip](get_one_zip.md): `GET https://api.mlsec.io/api/get_one_zip/<ID>?api_token={api_token}`

It may take several minutes for the status to show that the ZIP is ready.  Each sample must be submitted to each ML model (which counts against your API count on the leaderboard).  Those samples that evade all ML models are subsequently detonated in a sandbox to verify functionality of the original sample.  

Query status of all samples
* [get_all_sample](get_all_sample.md): `GET https://api.mlsec.io/api/get_all_sample/?api_token={api_token}`

Query status of a specific sample
* [get_one_sample](get_one_sample.md): `GET https://api.mlsec.io/api/get_one_sample/<ID>?api_token={api_token}`
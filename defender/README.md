# Defender Challenge
<!-- vscode-markdown-toc -->
* [Overview](#overview)
    * [Challenge dates](#challenge-dates)
    * [Rules / Terms](#rules-/-terms)
    * [Requirements](#requirements)
* [Build the sample solution](#build-the-sample-solution)
* [Modify the sample solution](#modify-the-sample-solution)
* [Frequently Asked Questions](#frequently-asked-questions)

<!-- vscode-markdown-toc-config
	numbering=false
	autoSave=true
	/vscode-markdown-toc-config -->
<!-- /vscode-markdown-toc -->

## <a name='overview'></a>Overview

### <a name='challenge-dates'></a>Challenge dates
Jun 15 – Jul 23, 2020 AoE (AoE)

### <a name='rules-/-terms'></a>Rules / Terms
[https://mlsec.io/tos](https://mlsec.io/tos)

### <a name='requirements'></a>Requirements
A valid submission for the defense track consists of the following
1. a Docker image no larger than 1 GB when _uncompressed_ (`gzip` compression required for upload)
2. listens on port 8080
3. accepts `POST /` with header `Content-Type: application/octet-stream` and the contents of a PE file in the body
4. returns `{"result": 0}` for benign files and `{"result": 1}` for malicious files (bytes `POST`ed as `Content-Type: application/json`)
5. must exhibit a false positive rate of less than 1% and a false negative rate of less than 10% (checked on upload, during and after the [Attacker Challenge](../attacker/) using randomly-selected files)
6. for files up to 2**21 bytes (2 MiB), must respond in less than 5 seconds (a timeout results in a benign verdict)

## <a name='build-the-sample-solution'></a>Build the sample solution
Before you proceed, you must [install Docker Engine](https://docs.docker.com/engine/install/) for your operating system.

A sample solution that you may modify is included in the `defender` folder. (See the [FAQ](FAQ.md#the-example-solution) for an overview of the example solution.) 

From the `defender` folder that contains the `Dockerfile`, build the solution:
```
docker build -t ember .
```

Run the docker container:
```
docker run -itp 8080:8080 ember
```
(The flag `-p 8080:8080` maps the container's port 8080 to the host's port 8080.)

Test the solution on malicious and benign samples of your choosing via:
```
python -m defender.test -m MLSEC_2019_samples_and_variants.zip -b C:\Windows\System32\ 
```
Sample collections may be in a folder, or in an archive of type `zip`, `tar`, `tar.bz2`, `tar.gz` or `tgz`.  `MLSEC_2019_samples_and_variants.zip` contains malware and evasive submissions from the 2019 evasion competition and may be downloaded from [https://mlsec.io/](https://mlsec.io) after registering or logging in.  **It is not required to unzip and strongly recommended that you do not unzip the archive to test malicious samples.** 


## <a name='modify-the-sample-solution'></a>Modify the sample solution
A sure way to submit a valid solution is to modify the example Python code and Dockerfile. Do this as follows:
1. Modify [defender/models/ember_model.py](defender/models/ember_model.py) or create a a new model file in [defender/models](defender/models).
    + Your Python class must include a `predict` method that [returns an integer](defender/defender/models/ember_model.py#L30-L32): `0` for benign and `1` for malicious.  (The code will appropriately wrap this result in a JSON response.)
2. In [defender/\_\_main\_\_.py](defender/__main__.py), [import your new model](defender/__main__.py#L5-L6), [instantiate your model](defender/__main__.py#L20-L25), and [include it in your app](defender/__main__.py#L27) via `app = create_app(model)`.
    + Tip: you may choose to [pass some model parameters](defender/__main__.py#L10-L14) (e.g., model file, threshold) via environmental variables so that you can tune these in the Dockerfile (faster builds!) rather than in the Python code.
3. Make sure to update [docker-requirements.txt](docker.requirements.txt) with any Python dependencies that you `import`ed when writing your code.
4. Modify the [Dockerfile](Dockerfile) to install any addiitonal binary dependencies.
5. Build your docker image using `docker build -t mydefender .` from the directory containing `DOCKERFILE`.  It is recommended that your registered username at [https://mlsec.io](https://mlsec.io) is consistent with the name of your docker image (i.e., change `mydefender` to your username).
6. Run your docker image using `docker run -itp 8080:8080 --memory=1.5g --cpus=1 mydefender`
    + Your hosted docker container will have a memory limit of 1.5G and a single CPU
7. Test your solution using `python -m defender.test -m MLSEC_2019_samples_and_variants.zip -b C:\Windows\System32\`.  
    + Malicious and benign samples may be contained in a folder, a ZIP (possibly encrypted with password `infected`), or a tarball (including `.gz` and `.bz2`).
8. If your image passes tests (FP/FN rates, etc.) in your offline tests (<1% FPR, <10% FPR), you are ready to upload it to the website.
    + Export your docker image `docker image save -o mydefender.tar mydefender`.  Replace `mydefender` with your username.
    + Ensure that your saved image `mydefender.tar` does not exceed 1 GB.
    + [GZIP](https://www.gnu.org/software/gzip/) your tar image via `gzip mydefender.tar` to create `mydefender.tar.gz`.
    + Login to the [website](https://mlsec.io) and upload `mydefender.tar.gz`.
    + Take a break. Validating the docker image may take some time. Please allow 20 minutes before checking the status of your upload.  The web portal will indicate whether your image has passed validation tests.

## <a name='frequently-asked-questions'></a>Frequently Asked Questions
For additional questions, the following resources are available:
* [Frequently Asked Questions](FAQ.md) markdown file with solutions to common problems
* [Join the Slack channel](https://join.slack.com/t/evademalwareml/shared_invite/zt-9birv1qf-KJFEiyLLRVtrsNDuyA0clA) to interact with other contestants
* [Submit an issue](https://github.com/Azure/2020-machine-learning-security-evasion-competition/issues) for issues relating to the sample code

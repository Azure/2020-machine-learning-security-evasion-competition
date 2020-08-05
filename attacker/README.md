# Attacker Challenge
<!-- vscode-markdown-toc -->
* [Overview](#overview)
    * [Challenge Dates](#challenge-dates)
    * [Rules / Terms](#rules-/-terms)
    * [Requirements](#requirements)
* [Sample solution](#sample-solution)
* [Reference](#reference)

<!-- vscode-markdown-toc-config
	numbering=false
	autoSave=true
	/vscode-markdown-toc-config -->
<!-- /vscode-markdown-toc -->


## <a name='overview'></a>Overview

### <a name='challenge-dates'></a>Challenge Dates
Aug 6 - Sep 18, 2020 (AoE)

### <a name='rules-/-terms'></a>Rules / Terms
[https://mlsec.io/tos](https://mlsec.io/tos)

### <a name='requirements'></a>Requirements
A valid submission for the attacker challenge consists of the following:
1. a ZIP file containing modified malware samples with their original names (`001`, `002`, etc.)
2. samples in the ZIP file have been verified as functional in a [Windows 10 Sandbox (disable networking!)](https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/)

## <a name='sample-solution'></a>Sample solution
<span style="color:red">**Only run this sample solution on a Linux virtual machine. It will write novel, functional malware samples to disk.**</span>

Watch a [demo video](https://drive.google.com/file/d/1ttCSGbwjNd2TpIF4SK6IznhArArRPRoX/view) of the example solution for more context.

The example solution is intended to simplify creating evasive malware samples that are functional using a semi-automated process.  After running this solution, it is possible that
1. some of the samples produced may not be functional afterall, or
2. no evasive variant is discovered for a set of samples.
Thus, manually verifying that samples are functional, and manually manipulating some samples to evade machine learning may still be required.

A sample solution that you may modify is included in the [attacker](attacker/) folder. (See the [FAQ](FAQ.md#the-example-solution) for an overview of the example solution.)

**Install UPX**

Download the latest release [here](https://github.com/upx/upx/releases/tag/v3.96), required for this sample solution.  

**Install Python requirements using `pip`**

```
pip install -r attacker/requirements.txt
```

**Initialize the attack**

In the example attack, PE file contest is extracted from a list of benign files that you provide.  You must also provide the `api_token` obtained from [https://mlsec.io/myuser](https://mlsec.io/myuser/).  From the root folder, run
```
python -m attacker.attacker init --benign ~/data/benign/ --api_token 0123456789abcdef0123456789abcdef -o config.pkl
```

**Offline attack: Discover evasive candidates**

The sample solution first attacks a _local_ black-box model that you must run.  We will use the defended ember model, which is identical to the `ember` model hosted for the competition.  Since the black-box models are report hard labels, as a heuristic, we'll average this score with a local version of (undefended) ember which reports a score.  This will help our optimization approach discover which file modifications might be fruitful, even if they do not result in a benign label.

Run the defended ember model in a separate terminal. (For more information, see the [defender documentation](../defender/README.md)):
```
pip install -r defender/requirements.txt
cd defender
python -m defender
```

Run the attack script against the model that is now being served locally, storing the samples in a new folder, `pass1`.  Those that bypass the local model will be stored in `pass1/success`, while those that do not will be stored in `pass1/failure`.
```
python -m attacker.attacker run --config config.pkl --samples ~/data/MLSEC_samples.zip --success_out pass1/success --failure_out pass1/failure --max-evals 10
```

We have allowed only 10 queries per malware sample via `--max-evals 10`. To continue exploring the space of file modifications for a universal bypass, one may optionally _resume_ optimizing via
```
python -m attacker.attacker run --config config.pkl --samples pass1/failure --success_out pass2/success --failure_out pass2/failure --max-evals 10
```

**Online attack: Discover evasive candidates**
After having collected a number of samples that evade the offline `defender` module, use them as seeds in an online attack by include the flag `--online`:

```
python -m attacker.attacker run --config config.pkl --samples candidates/ --success_out online_pass1/success --failure_out online_pass1/failure --max-evals 10 --online
```

As above, this process can be repeated for failed samples:

```
python -m attacker.attacker run --config config.pkl --samples online_pass1/failure --success_out online_pass2/success --failure_out online_pass2/failure --max-evals 10 --online
```

## <a name='reference'></a>Reference
For additional questions, the following resources are available:
* [REST API Interface](docs/API.md) API documentation for submitting samples and uploading ZIP files
* [Frequently Asked Questions](FAQ.md) markdown file with solutions to common problems
* [Join the Slack channel](https://join.slack.com/t/evademalwareml/shared_invite/zt-9birv1qf-KJFEiyLLRVtrsNDuyA0clA) to interact with other contestants
* [Submit an issue](https://github.com/Azure/2020-machine-learning-security-evasion-competition/issues) for issues relating to the sample code

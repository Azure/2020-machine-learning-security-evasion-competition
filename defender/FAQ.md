# Frequently Asked Questions

<!-- vscode-markdown-toc -->
* [The example solution](#the-example-solution)
    * [What does the example solution do?](#what-does-the-example-solution-do?)
* [Data sources](#data-sources)
    * [Where do I obtain training samples for my solution?](#where-do-i-obtain-training-samples-for-my-solution?)
    * [Where do I obtain samples to test or validate my solution?](#where-do-i-obtain-samples-to-test-or-validate-my-solution?)
* [Building a solution](#building-a-solution)
    * [The example DockerFile fails to build with `Release file for http://security.debian.org/debian-security/dists/buster/updates/InRelease is not valid yet`](#the-example-dockerfile-fails-to-build-with-`release-file-for-http://security.debian.org/debian-security/dists/buster/updates/inrelease-is-not-valid-yet`)
    * [How can I get my Docker image under 1 GB?](#how-can-i-get-my-docker-image-under-1-gb?)
* [Uploading and validating a solution](#uploading-and-validating-a-solution)
    * [Why was my solution rejected on upload?](#why-was-my-solution-rejected-on-upload?)
    * [What are the specs of the hosted docker container?](#what-are-the-specs-of-the-hosted-docker-container?)

<!-- vscode-markdown-toc-config
	numbering=false
	autoSave=true
	/vscode-markdown-toc-config -->
<!-- /vscode-markdown-toc -->


## <a name='the-example-solution'></a>The example solution

### <a name='what-does-the-example-solution-do?'></a>What does the example solution do?
The sample solution consists of the [EMBER model](https://github.com/endgameinc/ember), wrapped inside a stateful nearest-neighbor detector inspired by the method presented by [(Chen, et al. 2019)](https://arxiv.org/abs/1907.05587). A sample that the EMBER model scores as benign, but has a malicious nearest neighbor in the query history is considered an adversarial evasion attempt.  Since common evasion attacks include adding new sections, appending to sections, or appending to the overlay, in this implementation, nearest neighbors are computed with respect to byte-level features (histogram and byte-entropy features) derived from "stripped down" versions of the submitted binary. Each submitted binary is reduced to (up to) the first five sections, only (up to) the first 64k of each section is retained, and only (up to) the first 128 bytes of the overlay are retained. The nearest neighbor radius was set to achieve a small FP rate on binaries in `C:\Windows\System32\`, while still detecting a large fraction of evasive variants submitted in the 2019 competition.

The sample solution has not been extensively tuned.

## <a name='data-sources'></a>Data sources

### <a name='where-do-i-obtain-training-samples-for-my-solution?'></a>Where do I obtain training samples for my solution?
For convenience, it is recommended that you modify the example solution based on the [EMBER model](https://github.com/endgameinc/ember), for which [pre-computed features may be downloaded](https://github.com/endgameinc/ember#download) for benign and malicious files. This circumvents legal restrictions around sharing copyrighted benign files, especially.

Should you wish to train your own model from scratch, you are responsible for curating your own dataset. Unfortunately, we are unable to provide large collections of benign or malicious samples at this time.

### <a name='where-do-i-obtain-samples-to-test-or-validate-my-solution?'></a>Where do I obtain samples to test or validate my solution?
Malicious samples and evasive variants from the 2019 competition (`MLSEC_2019_samples_and_variants.zip`) may be downloaded from [https://mlsec.io/](https://mlsec.io) after registering or logging in.  **It is not required to unzip and strongly recommended that you do not unzip the archive to test malicious samples.** 

View the README file contained in `MLSEC_2019_samples_and_variants.zip` to understand how the contents are organized. Do this without extracting the full contents via
```
unzip -P infected -p MLSEC_2019_samples_and_variants.zip MLSEC_2019_samples_and_variants/README | less
```

## <a name='building-a-solution'></a>Building a solution

### <a name='the-example-dockerfile-fails-to-build-with-`release-file-for-http://security.debian.org/debian-security/dists/buster/updates/inrelease-is-not-valid-yet`'></a>The example DockerFile fails to build with `Release file for http://security.debian.org/debian-security/dists/buster/updates/InRelease is not valid yet`
This is usually caused by the Docker container clock being out of sync with the host clock.  Things you can try to fix this include:
* Restart the Docker (Docker Desktop on Windows) service
* If this doesn't work, modify every instance of `apt-get update` in your DockerFile with `-o Acquire::Max-FutureTime=86400`, and specify enough time (in seconds) to make the request valid. 86400 seconds is a single day.

### <a name='how-can-i-get-my-docker-image-under-1-gb?'></a>How can I get my Docker image under 1 GB?
It is strongly recommended that you lightly modify the example Dockerfile rather than writing your own.  Use 
```
docker system df -v
```
to view the size of your docker image after you've built it.  If your image exceeds 1 GB, check to make sure you're practicing good Dockerfile hygiene.

**We've found that the biggest waste of space are unused Python packages.  Be selective in what you `pip install`.**

There are a number of additional tricks that may help you reduce the size of your image that are implemented in the example Dockerfile.
* Use multiple commands per `RUN`.  Each `RUN` creates an additional image, which adds to space.  So, `RUN do_thing1 && do_thing2 && do_thing3` is more space efficient than three separate `RUN` commands.
* Use `--no-cache-dir` when doing `pip install`.
* Start with a small image in `FROM`. Beware of using base images that [may cause Python crashes](https://pythonspeed.com/articles/alpine-docker-python/).

## <a name='uploading-and-validating-a-solution'></a>Uploading and validating a solution

### <a name='why-was-my-solution-rejected-on-upload?'></a>Why was my solution rejected on upload?
A few things to check:
* Docker images are tar files. We accept `.tar.gz` files.  Did you `gzip` your Docker image?
* Is your Docker image (_before gzip_) less than 1 GB?

### <a name='what-are-the-specs-of-the-hosted-docker-container?'></a>What are the specs of the hosted docker container?
Your hosted docker container will have a memory limit of 1.5G and a single CPU.  Testing it offline with
```docker run -itp 8080:8080 --memory=1.5g --cpus=1 mydefender```
should scare out the memory/CPU bugs before you upload.


FROM python:3.7-slim

#############################
# INSTALL PYTHON DEPENDENCIES
#############################

# install git for pip install git+https://
RUN apt-get -o Acquire::Max-FutureTime=100000 update \
 && apt-get install -y --no-install-recommends build-essential git

# create a virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# copy and install python requirements + ember from github
COPY docker-requirements.txt .
RUN pip install --no-cache-dir -r docker-requirements.txt \
 && pip install --no-cache-dir git+https://github.com/endgameinc/ember.git

#############################
# REBASE & DEPLOY CODE
#############################

# rebase to make a smaller image
FROM python:3.7-slim

# required libgomp1 for ember
RUN apt-get -o Acquire::Max-FutureTime=100000 update \
    && apt-get -y --no-install-recommends install \
        libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# copy python virtual env (all dependencies) from previous image
COPY --from=0 /opt/venv /opt/venv

# copy defender code to /opt/defender/defender
COPY defender /opt/defender/defender

#############################
# SETUP ENVIRONMENT
#############################

# open port 8080
EXPOSE 8080

# add a defender user and switch user
RUN groupadd -r defender && useradd --no-log-init -r -g defender defender
USER defender

# change working directory
WORKDIR /opt/defender/

# update environmental variables
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONPATH="/opt/defender"

# one may tune model file / threshold / name via environmental variables
ENV DF_MODEL_GZ_PATH models/ember_model.txt.gz
ENV DF_MODEL_THRESH 0.8336
ENV DF_MODEL_NAME ember
ENV DF_MODEL_BALL_THRESH 0.25
ENV DF_MODEL_HISTORY 10000

#############################
# RUN CODE
#############################
CMD ["python","-m","defender"]

## TO BUILD IMAGE:
# docker build -t ember .
## TO RUN IMAGE (ENVIRONMENTAL VARIABLES DECLARED ABOVE)
# docker run -itp 8080:8080 ember
## TO RUN IMAGE (OVERRIDE ENVIRONMENTAL VARIABLES DECLARED ABOVE)
# docker run -itp 8080:8080 --env DF_MODEL_GZ_PATH="models/ember_model.txt.gz" --env DF_MODEL_THRESH=0.8336 --env DF_MODEL_NAME=myember ember

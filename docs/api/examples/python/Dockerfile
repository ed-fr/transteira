# Image of the express-secret.py self-test (docs/api/examples/examples_test.go): the pinned
# Python with the packages of requirements.txt, installed from wheels checked against their
# hashes. Built by the test with the folder docs/api/examples as context; the self-test then
# runs without network.
FROM python:3.13-alpine@sha256:1e1f6334529d1fb26a2ef619d7cffb30a7c7d7cc1cc7338ebee283a58d1aeaca
COPY requirements.txt /tmp/requirements.txt
RUN python -m pip install --no-cache-dir --disable-pip-version-check --root-user-action=ignore \
      --require-hashes --only-binary=:all: -r /tmp/requirements.txt \
 && rm /tmp/requirements.txt
USER nobody

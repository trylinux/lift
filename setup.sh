#!/bin/sh

# Basic install script
virtualenv --download -p python3 venv
source venv/bin/activate
python3 setup.py develop

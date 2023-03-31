#!/bin/sh

# Basic install script
virtualenv -p python3 venv
source venv/bin/activate
python3 setup.py develop

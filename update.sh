#!/bin/bash
set -e

env="$1"

if [ -z "$env" ]; then
    env="venv"
fi

if [ ! -d "$env" ]; then
  python3 -m venv "$env"
fi

source "$env/bin/activate"

git pull --rebase --autostash
pip uninstall -y binary-refinery
pip install -e .[full]
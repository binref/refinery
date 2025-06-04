#!/bin/bash
set -e
venv="$1"

if [ -z "$venv" ]; then
    venv="venv"
fi

if [ ! -d "$venv" ]; then
  python3 -m venv "$venv"
fi

source "$venv/bin/activate"

python -m pip install --upgrade pip

rm ./refinery/data/units.pkl

git pull --rebase --autostash
pip uninstall -y binary-refinery
pip install --use-pep517 -U -e .[all]
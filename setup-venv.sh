#!/bin/bash

venv="venv"
wheel=false

set -e

while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    -wheel)
      wheel=true && shift
    ;;
    -venv)
      venv="$2" && shift && shift
    ;;
    *)
      echo "usage: ./setup-venv.sh [-wheel] [-venv folder]"
      echo "  - the default folder for the virtual environment is: ${venv}"
      echo "  - installing as wheel may have performance benefits, but this install script"
      echo "    has to be invoked every time an update is pulled."
      exit
    ;;
  esac
done

if [ ! -d "$venv" ]; then
  echo -- please run setup-venv.py to create a virtual environment.
  exit
fi

source $venv/bin/activate

echo -- updating and installing required packages.

python -m pip install --upgrade pip
python -m pip uninstall -y --quiet binary-refinery 

if [ "$wheel" = true ] ; then
  echo -- installing requiements before wheel construction
  python -m pip install -r requirements.txt
  echo -- building wheel
  python -m pip install wheel
  python setup.py sdist bdist_wheel 2>&1 > /dev/null
  pushd dist
  python -m pip install $(ls *.whl)
  popd
else
  python -m pip install -e .
fi

deactivate

function realpath {
  echo $(cd $(dirname $1); pwd)/$(basename $1); 
}

echo -- to enable the refinery, update your PATH as follows:
echo
echo PATH=\$PATH:$(realpath $venv/bin)
echo
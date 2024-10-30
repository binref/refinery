param(
  [string] [ValidateNotNullOrEmpty()] $env = 'venv'
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $env)) {
    . py -3 -m venv $env
}

& "./$env/Scripts/Activate.ps1"

python -m pip install --upgrade pip

rm ./refinery/__init__.pkl

git pull --rebase --autostash
pip uninstall -y binary-refinery
pip install --use-pep517 -e .[all]
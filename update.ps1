param(
  [string] [ValidateNotNullOrEmpty()] $env = 'venv'
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $env)) {
    . py -3 -m venv $env
}

& "./$env/Scripts/Activate.ps1"

git pull --rebase --autostash
pip uninstall -y binary-refinery
pip install -e .[full]
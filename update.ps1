#!powershell
$ErrorActionPreference = "Stop"
$venv = "venv";

if ($args.Count -ge 1) {
    $venv = $args[0];
}

if (-not (Test-Path $venv)) {
    . py -3 -m venv $venv
}

. "$venv\Scripts\Activate.ps1"

python -m pip install --upgrade pip
try {
    rm ./refinery/data/units.pkl
} catch {}
git pull --rebase --autostash
pip uninstall -y binary-refinery
pip install --use-pep517 -U -e .[all]
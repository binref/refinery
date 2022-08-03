#!/usr/bin/zsh

function alias-noglob {
    while read -r entrypoint; do
        alias $entrypoint="noglob $entrypoint"
    done
}

python <<EOF | alias-noglob
import pkg_resources
for ep in pkg_resources.iter_entry_points('console_scripts'):
    if ep.module_name.startswith('refinery'):
        print(ep.name)
EOF

python fixitfixit.py %1/**/*.py
isort --py=38 %1
ef %1/**/*.py -l [| put p | run pyupgrade --py38-plus {} | pf upgraded: {p} ]]
autoflake --in-place --remove-all-unused-imports -r %1
isort --py=38 %1
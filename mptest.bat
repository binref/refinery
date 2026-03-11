if "%1"=="--cov" (
    @pytest -n auto -m "not cosmetics" --dist=loadgroup --disable-warnings --cov-config=.coveragerc --cov refinery test 2>NUL
) else (
    @pytest -n auto -m "not cosmetics" --dist=loadgroup --disable-warnings %* test 2>%~n0.errors
)
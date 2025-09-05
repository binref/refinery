#!/bin/bash
pytest -n auto -m "not cosmetics" --dist=loadgroup --disable-warnings test
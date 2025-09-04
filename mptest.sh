#!/bin/bash
pytest -n auto -m "not clipboard and not cosmetics" --dist=loadgroup --disable-warnings test
pytest -n  0   -m "    clipboard and not cosmetics" --dist=loadgroup --disable-warnings test
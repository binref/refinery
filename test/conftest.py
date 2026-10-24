"""
Three differentials, each an option that runs a whole test selection under a cost device turned off:

- `--no-pin` neutralizes every model-cache pin, so each model read observes the current tree. A pin
  is a cost device, never a semantic one — the obligation
  `refinery.lib.scripts.modelcache.ModelCacheBase.pinned` states — so any test that fails only under
  this option has found a pass acting on a stale answer. Build-count pins measure the cost the pin
  itself buys and skip themselves through the `REFINERY_TEST_NO_PIN` environment variable this
  option sets before collection.

- `--no-batch` turns every batched pass into its sequential self, each decided plan applied the
  moment it is decided and against the model the tree then warrants. A batch is a cost device the
  same way a pin is — the obligation
  `refinery.lib.scripts.js.deobfuscation.helpers.BatchedTransformer` states — so any test that
  fails only under one of the two modes has found a pass whose batch diverges from its sequential
  self. Tests that count builds or edits measure what the batch itself buys and skip themselves
  through the `REFINERY_TEST_NO_BATCH` environment variable this option sets before collection.

- `--no-node-answers` asks Node about every program instead of giving the answer it kept from an
  earlier run. A kept answer is a cost device as well, so any test that fails only under this
  option was given an answer that Node no longer gives.

Node's answers to the JavaScript oracle are kept between runs in pytest's cache folder, which this
module names in the `REFINERY_TEST_NODE_ANSWERS` environment variable unless that is set already:
`--cache-clear` empties it, and without the cache provider, or where its folder cannot be created,
nothing is kept. `--no-node-answers` empties the variable, which keeps nothing either. Which answers
are kept, and when they are dropped, is `test.lib.scripts.js.analysis.differential.NodeAnswers`.
"""
from __future__ import annotations

import os

from contextlib import contextmanager, suppress


def pytest_addoption(parser):
    parser.addoption(
        '--no-pin',
        action='store_true',
        default=False,
        help='neutralize every model-cache pin and run the selection as a differential',
    )
    parser.addoption(
        '--no-batch',
        action='store_true',
        default=False,
        help=(
            'apply every batched pass edit as it is decided and run the selection as a differential'
        ),
    )
    parser.addoption(
        '--no-node-answers',
        action='store_true',
        default=False,
        help='ask Node about every program instead of giving the answers kept from earlier runs',
    )


def pytest_configure(config):
    if config.getoption('--no-node-answers'):
        os.environ['REFINERY_TEST_NODE_ANSWERS'] = ''
    elif (cache := getattr(config, 'cache', None)) is not None:
        with suppress(OSError):
            os.environ.setdefault('REFINERY_TEST_NODE_ANSWERS', str(cache.mkdir('node-answers')))
    if config.getoption('--no-pin'):
        os.environ['REFINERY_TEST_NO_PIN'] = '1'
        from refinery.lib.scripts.modelcache import ModelCacheBase

        @contextmanager
        def unpinned(self):
            yield self

        ModelCacheBase.pinned = unpinned
    if config.getoption('--no-batch'):
        os.environ['REFINERY_TEST_NO_BATCH'] = '1'
        from refinery.lib.scripts.js.deobfuscation.helpers import BatchedTransformer

        BatchedTransformer.batching = False

from __future__ import annotations

from test import TestBase

from refinery.lib.scripts import Script
from refinery.lib.scripts.analysis.cfg import CfgBuilder, Projection, flood


class TestAFloodFromSeveralSourcesIsTheUnionOfTheirFloods(TestBase):

    def test_a_hub_bound_source_walks_on_through_a_source_the_precise_walk_owns(self):
        builder = CfgBuilder(Script())
        handled = builder.synthetic_node()
        guarded = builder.synthetic_node()
        hub = builder.resumption_hub()
        resumed = builder.synthetic_node()
        builder.mark_hub_bound([handled])
        builder.add_edge(handled, guarded)
        builder.add_edge(guarded, hub)
        builder.resumption_hub_edge(hub, resumed)
        self.assertEqual(
            flood([handled, guarded], forward=True, projection=Projection.FORWARD),
            flood([handled], forward=True, projection=Projection.FORWARD)
            | flood([guarded], forward=True, projection=Projection.FORWARD),
        )

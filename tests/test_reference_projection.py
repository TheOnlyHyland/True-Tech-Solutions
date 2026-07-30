"""Tests for typed semantic entity-reference projection."""

from __future__ import annotations

import importlib
from pathlib import Path
import sys
import types
import unittest


ROOT = Path(__file__).parents[1]
PACKAGE_ROOT = ROOT / "custom_components" / "true_family"
PACKAGE_NAME = "custom_components.true_family"
OLD_ENTITY = "climate.kitchen_radiator"
TARGET_ENTITY = "climate.true_family_kitchen_valve"


def load_projection():
    custom_components = sys.modules.setdefault(
        "custom_components", types.ModuleType("custom_components")
    )
    custom_components.__path__ = [str(ROOT / "custom_components")]
    package = sys.modules.setdefault(PACKAGE_NAME, types.ModuleType(PACKAGE_NAME))
    package.__path__ = [str(PACKAGE_ROOT)]
    return importlib.import_module(f"{PACKAGE_NAME}.reference_projection")


projection = load_projection()


class ReferenceProjectionTests(unittest.TestCase):
    def test_complete_scalars_and_lists_are_replaceable(self) -> None:
        payload = {
            "entity_id": OLD_ENTITY,
            "entities": [OLD_ENTITY, "climate.kitchen_radiator_with_term"],
        }

        scan = projection.scan_semantic_references(payload, OLD_ENTITY)
        replaced, count = projection.replace_semantic_references(
            payload,
            OLD_ENTITY,
            TARGET_ENTITY,
        )

        self.assertEqual(scan.replaceable_paths, (("entities", 0), ("entity_id",)))
        self.assertEqual(scan.blocked, ())
        self.assertEqual(count, 2)
        self.assertEqual(replaced["entity_id"], TARGET_ENTITY)
        self.assertEqual(
            replaced["entities"][1],
            "climate.kitchen_radiator_with_term",
        )

    def test_approved_literal_helpers_preserve_template_text(self) -> None:
        helpers = ("states", "state_attr", "is_state", "is_state_attr", "has_value")
        providers = (None, "active_yaml", "config_entry", "lovelace")
        for helper in helpers:
            for provider in providers:
                with self.subTest(helper=helper, provider=provider):
                    payload = {
                        "value_template": f"{{{{ {helper}('{OLD_ENTITY}') }}}}",
                    }
                    scan = projection.scan_semantic_references(
                        payload,
                        OLD_ENTITY,
                        provider=provider,
                    )
                    replaced, count = projection.replace_semantic_references(
                        payload,
                        OLD_ENTITY,
                        TARGET_ENTITY,
                        provider=provider,
                    )

                    self.assertEqual(scan.replaceable_paths, (("value_template",),))
                    self.assertEqual(scan.blocked, ())
                    self.assertEqual(count, 1)
                    self.assertEqual(
                        replaced["value_template"],
                        f"{{{{ {helper}('{TARGET_ENTITY}') }}}}",
                    )

    def test_comments_and_filters_are_preserved_exactly(self) -> None:
        target = f"{OLD_ENTITY}_with_term"
        template = (
            f"{{# Keep documentation for {OLD_ENTITY} #}}"
            f"{{{{ states('{OLD_ENTITY}') | float + 1 }}}}"
            "\r\n"
        )
        payload = {"value_template": template}

        replaced, count = projection.replace_semantic_references(
            payload,
            OLD_ENTITY,
            target,
            provider="active_yaml",
        )
        post_scan = projection.scan_semantic_references(
            replaced,
            OLD_ENTITY,
            provider="active_yaml",
        )

        self.assertEqual(count, 1)
        self.assertEqual(
            replaced["value_template"],
            template.replace(
                f"states('{OLD_ENTITY}')",
                f"states('{target}')",
            ),
        )
        self.assertEqual(post_scan.replaceable_paths, ())
        self.assertEqual(post_scan.blocked, ())

    def test_longer_facade_template_is_not_an_old_reference(self) -> None:
        facade = f"{OLD_ENTITY}_with_term"
        payload = {
            "value_template": f"{{{{ states('{facade}') ~ ' C' }}}}",
        }

        scan = projection.scan_semantic_references(
            payload,
            OLD_ENTITY,
            provider="active_yaml",
        )

        self.assertEqual(scan.replaceable_paths, ())
        self.assertEqual(scan.blocked, ())

    def test_syntax_aware_template_failures_are_blocked(self) -> None:
        templates = (
            f"{{{{ states.climate.kitchen_radiator.state }}}}",
            f"{{{{ states['climate']['kitchen_radiator'].state }}}}",
            "{{ states(['climate', 'kitchen_radiator'] | join('.')) }}",
            "{{ states('{}.{}'.format('climate', 'kitchen_radiator')) }}",
            f"{{{{ mystates('{OLD_ENTITY}') }}}}",
            f"{{{{ hass.states('{OLD_ENTITY}') }}}}",
            f"{{{{ \"states('{OLD_ENTITY}')\" }}}}",
            f"states('{OLD_ENTITY}') {{{{ 1 }}}}",
            f"{{% raw %}}{{{{ states('{OLD_ENTITY}') }}}}{{% endraw %}}",
            f"{{{{ states('{OLD_ENTITY}' ~ suffix) }}}}",
            "{{ 'climate.' ~ 'kitchen_radiator' }}",
            "{{ states | attr('climate') | attr('kitchen_radiator') }}",
            "{{ states | attr(domain_name) | attr(object_name) }}",
            "{{ expand('climate.' ~ 'kitchen_' ~ 'radiator') }}",
            (
                "{{ device_id('light.kitchen_radiator' "
                "| replace('light', 'climate')) }}"
            ),
            (
                "{{ is_hidden_entity('light.kitchen_radiator' "
                "| replace('light', 'climate')) }}"
            ),
            (
                "{{ ['light.kitchen_radiator' "
                "| replace('light', 'climate')] | expand | list }}"
            ),
            "{{ 'light.safe climate.' ~ 'kitchen_radiator' }}",
            f"{{{{ states(('{OLD_ENTITY}')) }}}}",
            (
                f"{{# states('{OLD_ENTITY}') #}}"
                f"{{{{ states(('{OLD_ENTITY}')) }}}}"
            ),
            (
                "{% set states = helper %}"
                f"{{{{ states('{OLD_ENTITY}') }}}}"
            ),
            (
                "{% macro wrapper(states) %}"
                f"{{{{ states('{OLD_ENTITY}') }}}}"
                "{% endmacro %}"
            ),
            (
                "{% call(states) wrapper() %}"
                f"{{{{ states('{OLD_ENTITY}') }}}}"
                "{% endcall %}"
            ),
            (
                "{% set s = states %}"
                "{{ s.climate.kitchen_radiator.state }}"
            ),
            "{{ wrapper.source.climate.kitchen_radiator.state }}",
            "{{ get_source().climate.kitchen_radiator.state }}",
            (
                "{% macro wrapper(source) %}"
                "{{ source.climate.kitchen_radiator.state }}"
                "{% endmacro %}"
                "{{ wrapper(states) }}"
            ),
        )

        for template in templates:
            with self.subTest(template=template):
                payload = {
                    "value_template": template,
                }
                scan = projection.scan_semantic_references(
                    payload,
                    OLD_ENTITY,
                    provider="active_yaml",
                )

                self.assertEqual(scan.replaceable_paths, ())
                self.assertEqual(len(scan.blocked), 1)

    def test_unknown_free_text_keys_duplicates_and_computed_values_block(self) -> None:
        payloads = (
            {"note": f"Use {OLD_ENTITY} now"},
            {"note": OLD_ENTITY},
            {"entities": [{"note": OLD_ENTITY}]},
            {
                "entity_id": (
                    "{{ ['climate', 'kitchen_radiator'] | join('.') }}"
                )
            },
            {f"target {OLD_ENTITY}": "value"},
            {f"states.{OLD_ENTITY}.state": "value"},
            {"value_template": f"{{{{ unknown('{OLD_ENTITY}') }}}}"},
            {
                "value_template": (
                    f"{{{{ states('{OLD_ENTITY}') or states('{OLD_ENTITY}') }}}}"
                )
            },
            {
                "value_template": (
                    "{{ states('climate.' ~ 'kitchen_radiator') }}"
                )
            },
        )

        for payload in payloads:
            with self.subTest(payload=payload):
                scan = projection.scan_semantic_references(payload, OLD_ENTITY)
                self.assertEqual(scan.replaceable_paths, ())
                self.assertEqual(len(scan.blocked), 1)

    def test_non_template_providers_do_not_accept_template_rewrites(self) -> None:
        payload = {"value_template": f"{{{{ states('{OLD_ENTITY}') }}}}"}

        for provider in ("scheduler", "external_writers"):
            with self.subTest(provider=provider):
                scan = projection.scan_semantic_references(
                    payload,
                    OLD_ENTITY,
                    provider=provider,
                )

                self.assertEqual(scan.replaceable_paths, ())
                self.assertEqual(len(scan.blocked), 1)

    def test_scalar_fields_are_provider_specific(self) -> None:
        payload = {"heater": OLD_ENTITY}

        active = projection.scan_semantic_references(
            payload,
            OLD_ENTITY,
            provider="active_yaml",
        )
        scheduler = projection.scan_semantic_references(
            payload,
            OLD_ENTITY,
            provider="scheduler",
        )

        self.assertEqual(active.replaceable_paths, (("heater",),))
        self.assertEqual(active.blocked, ())
        self.assertEqual(scheduler.replaceable_paths, ())
        self.assertEqual(len(scheduler.blocked), 1)


if __name__ == "__main__":
    unittest.main()

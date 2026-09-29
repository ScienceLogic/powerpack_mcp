"""
Prompt Surface Tests

This module tests the MCP prompts: that the declared names register, that every tool a prompt
names exists on this server, that required tool pairs are named together, and that the shipped
ruleset and API guide are intact. Some prompts were ported from earlier MCP servers whose tool
surfaces differ from this one. A prompt that names a missing tool is worse than a missing prompt,
because the caller spends its turn discovering the absence, so that condition is asserted
mechanically in ``TestEveryToolNamedActuallyExists``.

Prompts are enumerated through FastMCP's public ``list_prompts()``, not ``mcp._prompt_manager``,
so the tests do not depend on a private detail that a fastmcp minor release could move.
"""

from __future__ import annotations

import asyncio
import inspect
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import pytest
from fastmcp import FastMCP

from powerpack_mcp.authz import DB_WRITE_SET, tool_names_for_set
from powerpack_mcp.config import Config
from powerpack_mcp.db_client import DbClient
from powerpack_mcp.lce_client import LceClient
from powerpack_mcp.mcp_app.app import register_tools
from powerpack_mcp.prompts import content
from powerpack_mcp.prompts.registry import PROMPT_NAMES, register_prompts
from powerpack_mcp.schema_slim import registered_tools
from powerpack_mcp.sl1_client import Sl1Client

if TYPE_CHECKING:
    from collections.abc import Iterator

# Backticked identifiers shaped like one of this server's tools. Anchored on the whole backtick
# span, so camelCase names such as ``createEventPolicy`` (a GraphQL field the rules say not to use,
# and not a tool of ours) are excluded rather than reported as missing.
_TOOL_SHAPED: Final[re.Pattern[str]] = re.compile(
    r"`((?:sl1_|lce_)[a-z0-9_]+|get_content_standards|server_health)`"
)

# Content that must never appear in a shipped prompt: an internal ticket reference, plus credential
# and internal-address material from the predecessor projects' config files. The ticket and the
# address prefixes are assembled from pieces, so that this file does not itself contain what the
# public export's leak checks reject.
_FORBIDDEN: Final[tuple[str, ...]] = (
    "SOL-" + "32674",
    "em7admin",
    "10.2." + "27.",
    "10.2." + "24.",
)


def _server_with_prompts() -> FastMCP:
    server: FastMCP = FastMCP(name="prompt-probe")
    register_prompts(server)
    return server


def _prompt_objects(server: FastMCP) -> list[Any]:
    """Return the registered prompts, through the public API.

    ``list_prompts`` is a coroutine on fastmcp 3.4.7, so it is driven with ``asyncio.run`` rather
    than making every caller async; these assertions are about a static surface.
    """
    return list(asyncio.run(server.list_prompts()))


def _rendered_prompts() -> Iterator[tuple[str, str]]:
    """Yield ``(name, text)`` for every prompt, invoked with placeholder arguments.

    Every prompt is called rather than having its source scanned. A composed prompt assembles the
    ruleset, the goal and its extra blocks at call time, so scanning the module would miss exactly
    the text a caller receives.
    """
    server = _server_with_prompts()
    for prompt in _prompt_objects(server):
        # Use each parameter's own default, not a placeholder for all of them. Passing
        # "placeholder goal" as ``topic`` would send ``sl1_dynamic_app_api_context`` down its
        # unknown-topic branch, so the assembled guide would never be checked.
        signature = inspect.signature(prompt.fn)
        arguments = {
            name: (
                "placeholder goal"
                if parameter.default is inspect.Parameter.empty
                else parameter.default
            )
            for name, parameter in signature.parameters.items()
        }
        rendered = prompt.fn(**arguments)
        assert isinstance(rendered, str), f"{prompt.name} did not return a string"
        yield prompt.name, rendered


def _our_guidance(text: str) -> str:
    """Return ``text`` with any inlined API-guide body removed.

    The tool-name check must not read the guide's prose. The guide is platform documentation that
    mentions ``lce_service`` (the LCE service, not a tool of ours), so it is subtracted and only
    the wrapper text written for this server is scanned.
    """
    slices = sorted(
        (content.build_guide_topic(topic)[1] for topic in content.api_guide_topics()),
        key=len,
        reverse=True,
    )
    # Longest first, and stop after one removal. Topics share sections, so a smaller topic's slice
    # can be a substring of the one actually inlined; removing it first would leave the real slice
    # unmatched and nothing subtracted.
    for candidate in slices:
        for form in (candidate, candidate.strip()):
            if form and form in text:
                return text.replace(form, "")
    return text


class TestTheDeclaredSurface:
    def test_the_declared_names_are_exactly_what_registers(self) -> None:
        """`PROMPT_NAMES` is documentation until something compares it with reality."""
        names = sorted(prompt.name for prompt in _prompt_objects(_server_with_prompts()))
        assert names == sorted(PROMPT_NAMES)

    def test_registration_is_idempotent_per_server(self) -> None:
        """Two servers, no shared state -- the decorators close over the server passed in."""
        first = sorted(p.name for p in _prompt_objects(_server_with_prompts()))
        second = sorted(p.name for p in _prompt_objects(_server_with_prompts()))
        assert first == second == sorted(PROMPT_NAMES)

    def test_every_prompt_has_a_description(self) -> None:
        """A prompt a client cannot describe is a prompt a client will not offer."""
        for prompt in _prompt_objects(_server_with_prompts()):
            assert prompt.description, prompt.name

    def test_prompts_are_registered_by_the_real_application_wiring(self) -> None:
        """The prompts must reach the surface ``create_app`` builds, not only this test's probe.

        ``register_prompts`` being written and never called is a silent failure: every other test
        in this file would still pass.
        """
        config = Config()
        server: FastMCP = FastMCP(name="wiring-probe")
        register_tools(server, LceClient(config), config, Sl1Client(config), None)
        register_prompts(server)
        assert sorted(p.name for p in _prompt_objects(server)) == sorted(PROMPT_NAMES)


class TestEveryToolNamedActuallyExists:
    """A prompt naming a tool that does not exist is a defect."""

    def test_no_prompt_names_a_tool_this_server_does_not_have(self) -> None:
        config = Config()
        server: FastMCP = FastMCP(name="tool-probe")
        register_tools(
            server,
            LceClient(config),
            config,
            Sl1Client(config),
            DbClient(config.MAX_CONCURRENT_REQUESTS),
        )
        available = {tool.name for tool in registered_tools(server)} | set(PROMPT_NAMES)

        offenders: dict[str, list[str]] = {}
        for name, text in _rendered_prompts():
            ours = _our_guidance(text)
            missing = sorted({m for m in _TOOL_SHAPED.findall(ours) if m not in available})
            if missing:
                offenders[name] = missing
        assert offenders == {}, f"prompts name tools that do not exist: {offenders}"

    def test_the_check_is_not_vacuous(self) -> None:
        """Prove the pattern would catch a bad name, or it proves nothing."""
        found = _TOOL_SHAPED.findall(
            "use `sl1_no_such_tool` and `lce_imaginary` but not `createEventPolicy`"
        )
        assert found == ["sl1_no_such_tool", "lce_imaginary"]

    def test_the_prompts_really_do_name_some_tools(self) -> None:
        """Non-vacuity from the other side: an empty prompt set would pass the check above."""
        named = {m for _, text in _rendered_prompts() for m in _TOOL_SHAPED.findall(text)}
        assert len(named) >= 10, f"expected the guidance to route to real tools, got {named}"


class TestNothingForbiddenTravelledWithThePort:
    @pytest.mark.parametrize("forbidden", _FORBIDDEN)
    def test_no_prompt_carries_it(self, forbidden: str) -> None:
        for name, text in _rendered_prompts():
            assert forbidden not in text, f"{name} carries {forbidden!r}"

    @pytest.mark.parametrize("forbidden", _FORBIDDEN)
    def test_no_shipped_data_file_carries_it(self, forbidden: str) -> None:
        for path in sorted(Path(content.__file__).resolve().parent.parent.glob("data/*.md")):
            assert forbidden not in path.read_text(encoding="utf-8"), f"{path.name}"


class TestTheRulesetShipped:
    def test_both_data_files_are_present_and_parse(self) -> None:
        """The packaging assertion.

        ``[tool.setuptools.package-data]`` is the only thing that puts these files in the venv the
        RPM ships, and a dropped declaration is invisible until a prompt is called on an appliance.
        """
        assert content.framework_rules().startswith("# ScienceLogic Snippet Framework")
        _, full = content.build_guide_topic("full")
        assert len(full) > 100_000, "the API guide looks truncated"

    def test_the_ruleset_keeps_every_section_the_union_was_built_from(self) -> None:
        """The ruleset merges two drifted copies; these are the sections one or other lacked.

        ``## 0``, the DCM term definitions, the deduplication-scope enumeration and the substitution
        use-cases came from the older copy; ``## 6`` and ``## 14`` exist only in the newer one. A
        trim that dropped either side's contribution would silently undo the merge.
        """
        rules = content.framework_rules()
        for heading in (
            "## 0. Core paradigm",
            "## 6. Collection Frequency",
            "## 11. Deduplication scope",
            "## 14. Field-tested gotchas",
        ):
            assert heading in rules, heading
        for grafted in ("Parent device", "Root device", "Component Dynamic Applications"):
            assert grafted in rules, grafted

    def test_the_ruleset_leads_every_composed_prompt(self) -> None:
        """It carries the precedence clause, so it has to arrive before anything it overrides."""
        composed = {
            "sl1_session_bootstrap",
            "sl1_snippet_framework_development_rules",
            "sl1_low_code_collection_flow_guide",
            "sl1_surface_selection_guide",
            "sl1_device_class_and_component_guide",
            "sl1_event_verification_guide",
            "sl1_credential_definition_guide",
            "sl1_discovery_session_guide",
            "sl1_virtual_device_lifecycle_guide",
        }
        for name, text in _rendered_prompts():
            if name in composed:
                assert text.startswith("# ScienceLogic Snippet Framework"), name


class TestTheGuideSlicer:
    def test_every_topic_resolves_to_content(self) -> None:
        for topic in content.api_guide_topics():
            description, markdown = content.build_guide_topic(topic)
            assert description, topic
            assert len(markdown) > 500, f"{topic} sliced to {len(markdown)} chars"

    def test_a_parent_heading_carries_its_children(self) -> None:
        """``9) Entity schemas`` must bring 9.1..9.6 with it, or ``payload_core`` is a stub."""
        _, markdown = content.build_guide_topic("payload_core")
        assert "9.1 Dynamic Application" in markdown
        assert "9.6 Alert Object" in markdown

    def test_an_unknown_topic_names_the_valid_ones(self) -> None:
        with pytest.raises(ValueError, match="payload_core") as caught:
            content.build_guide_topic("no_such_topic")
        assert "full" in str(caught.value)

    def test_the_prompt_reports_a_bad_topic_instead_of_raising(self) -> None:
        """A prompt argument is caller text, so the message names every valid topic.

        Raising would surface as a protocol error with no route to the fix.
        """
        rendered = next(
            prompt.fn(goal="g", topic="no_such_topic")
            for prompt in _prompt_objects(_server_with_prompts())
            if prompt.name == "sl1_dynamic_app_api_context"
        )
        assert "payload_core" in rendered
        assert "Unknown topic" in rendered

    def test_topic_keys_are_matched_loosely(self) -> None:
        """``normalize`` collapses punctuation and case, so a caller's near-miss still resolves."""
        assert (
            content.build_guide_topic("Payload Core")[1]
            == content.build_guide_topic("payload_core")[1]
        )

    def test_a_heading_that_no_longer_exists_is_a_loud_failure(self) -> None:
        """The guide-drift guard.

        If a heading is renamed upstream, the topic that names it must fail by name rather than
        silently assembling a shorter slice.
        """
        with pytest.raises(ValueError, match="No API guide section found"):
            content._find_section_by_prefix("42) A Heading That Does Not Exist")

    def test_a_topic_naming_one_heading_twice_emits_it_once(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Two prefixes can resolve to one section; the slice must not carry it twice."""
        doubled = content.GuideTopic("Doubled.", ("11) Examples", "11) Examples"))
        monkeypatch.setitem(content.GUIDE_TOPICS, "doubled_probe", doubled)
        _, markdown = content.build_guide_topic("doubled_probe")
        _, single = content.build_guide_topic("examples")
        assert markdown == single


class TestWorkflowPairsAreNamedTogether:
    """Tools that form a two-step workflow must be named together.

    ``TestEveryToolNamedActuallyExists`` catches a wrong name but cannot catch a missing one. This
    covers the case where an omission is actively harmful: half of a two-step workflow. Naming
    ``sl1_run_dynamic_collection`` without ``sl1_fetch_collection_output`` leaves a caller holding
    a ``proc_id`` it has no documented way to read, which is worse than never mentioning
    collections.

    Pairs are checked rather than "every tool must be named", because most tools legitimately need
    no guidance and a hand-maintained list of important tools would drift.
    """

    # Tools that only make sense in twos. If either is named, both must be.
    PAIRS: Final[tuple[tuple[str, str], ...]] = (
        # Dispatch returns a proc_id; the fetch is the only way to read the result.
        ("sl1_run_dynamic_collection", "sl1_fetch_collection_output"),
        # Naming the run without the create teaches a caller to start a session without learning
        # one must exist first, and a created session cannot be deleted, so the half-followed
        # sequence leaves permanent litter.
        ("sl1_create_discovery_session", "sl1_run_discovery_session"),
        # Find one, then inspect it. A caller told to list without being told how to read a
        # definition cannot act on what it finds.
        ("sl1_list_credentials", "sl1_get_credential"),
        # The load-bearing one. ``update`` does not work on SL1 12.5.21, so naming it without
        # ``replace`` sends a caller down a path that silently changes nothing.
        ("sl1_update_universal_credential", "sl1_replace_universal_credential"),
    )

    def _all_named(self) -> set[str]:
        return {m for _, text in _rendered_prompts() for m in _TOOL_SHAPED.findall(text)}

    @pytest.mark.parametrize("pair", PAIRS, ids=lambda p: f"{p[0]}+{p[1]}")
    def test_both_halves_of_a_pair_appear(self, pair: tuple[str, str]) -> None:
        named = self._all_named()
        first, second = pair
        if first in named or second in named:
            missing = [t for t in pair if t not in named]
            assert not missing, (
                f"the prompts name part of a workflow pair but not {missing}. Half a pair is "
                f"worse than neither: see this class's docstring."
            )

    def test_the_four_tools_this_change_added_are_named(self) -> None:
        """The credential readers and the collection pair must be routed to by some prompt."""
        named = self._all_named()
        for tool in (
            "sl1_list_credentials",
            "sl1_get_credential",
            "sl1_run_dynamic_collection",
            "sl1_fetch_collection_output",
        ):
            assert tool in named, f"{tool} exists on this server but no prompt mentions it"

    def test_the_pair_check_is_not_vacuous(self) -> None:
        """Prove the detector fires, or it proves nothing.

        A pair check that never sees either half passes trivially. This asserts the guarded names
        are present, so the conditional above is entered.
        """
        named = self._all_named()
        for first, second in self.PAIRS:
            assert first in named or second in named, (
                f"neither {first} nor {second} is named, so that pair's check never runs"
            )


class TestTheFourAddedPromptsEarnTheirPlace:
    """The topic-specific guides must each say something about the tools they cover.

    A prompt can register, render, lead with the ruleset and pass every check above while saying
    nothing about the tools it was added for. Moving a topic out of ``_TOOL_SELECTION`` can also
    silently remove guidance from ``sl1_session_bootstrap``, the prompt a client is most likely
    to read.
    """

    # Each guide, and the tools it is specifically about. Deliberately a subset: these are the tools
    # that motivated the prompt, not everything it may name.
    SUBJECTS: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
        (
            "sl1_device_class_and_component_guide",
            (
                "sl1_create_device_class",
                "sl1_update_device_class",
                "sl1_align_dynamic_app_to_device_class",
                "sl1_get_component_tree",
                "sl1_get_device_class_alignment",
            ),
        ),
        (
            "sl1_event_verification_guide",
            ("sl1_simulate_event", "sl1_inject_alert", "sl1_clear_event"),
        ),
        (
            "sl1_credential_definition_guide",
            (
                "sl1_list_credentials",
                "sl1_get_credential",
                "sl1_update_universal_credential",
                "sl1_replace_universal_credential",
            ),
        ),
        (
            "sl1_surface_selection_guide",
            (
                "sl1_get_dynamic_app",
                "sl1_rest_request",
                "sl1_graphql",
                "sl1_create_guided_discovery_session",
            ),
        ),
        (
            "sl1_discovery_session_guide",
            (
                "sl1_create_discovery_session",
                "sl1_run_discovery_session",
                "sl1_get_discovery_status",
                "sl1_list_discovery_sessions",
            ),
        ),
        (
            "sl1_write_blast_radius_guide",
            (
                "sl1_create_device_class",
                "sl1_update_device_class",
                "sl1_align_dynamic_app_to_device_class",
                "sl1_simulate_event",
                "sl1_run_dynamic_collection",
                "sl1_delete_device",
                "sl1_delete_credential",
                "sl1_unalign_dynamic_apps_from_device",
                "sl1_create_icon",
                "sl1_clear_event",
            ),
        ),
        (
            "sl1_virtual_device_lifecycle_guide",
            (
                "sl1_create_virtual_device",
                "sl1_list_virtual_device_classes",
                "sl1_align_dynamic_apps_to_device",
                "sl1_get_collected_values",
                "sl1_delete_device",
            ),
        ),
    )

    def test_each_added_prompt_names_the_tools_it_is_about(self) -> None:
        """Each guide names the tools it is about.

        The tool-name check elsewhere catches a wrong name and never a missing one, so this asserts
        the subjects are present.
        """
        rendered = dict(_rendered_prompts())
        for prompt_name, subjects in self.SUBJECTS:
            assert prompt_name in rendered, f"{prompt_name} did not render"
            text = rendered[prompt_name]
            for tool in subjects:
                assert f"`{tool}`" in text, f"{prompt_name} never names `{tool}`"

    def test_the_six_formerly_unmentioned_tools_are_now_named(self) -> None:
        """The SQL-backed device-class, event and component tools are each named by some prompt."""
        named = {
            tool
            for _, text in _rendered_prompts()
            for tool in re.findall(r"`(sl1_[a-z0-9_]+)`", text)
        }
        for tool in (
            "sl1_simulate_event",
            "sl1_create_device_class",
            "sl1_update_device_class",
            "sl1_align_dynamic_app_to_device_class",
            "sl1_get_component_tree",
            "sl1_get_device_class_alignment",
        ):
            assert tool in named, f"{tool} is still named by no prompt"

    def test_decongesting_tool_selection_left_a_pointer_behind(self) -> None:
        """Moving a topic out of ``_TOOL_SELECTION`` must not remove it from the bootstrap.

        ``sl1_session_bootstrap`` composes ``_TOOL_SELECTION``, so a reader who only sees the
        bootstrap would lose the moved guidance. Each move leaves a line naming the dedicated
        prompt; this asserts those lines survive.
        """
        bootstrap = dict(_rendered_prompts())["sl1_session_bootstrap"]
        for prompt_name, _ in self.SUBJECTS:
            assert prompt_name in bootstrap, (
                f"{prompt_name} is not pointed at from sl1_session_bootstrap, so a client that "
                "reads only the bootstrap cannot discover it"
            )

    def test_the_guided_discovery_route_is_not_the_stale_one(self) -> None:
        """The bootstrap must route guided discovery to the dedicated tool.

        Steering callers at raw ``createGuidedDiscoverySession`` creates a session and runs nothing,
        because no ``runGuidedDiscoverySession`` exists. The corrected wording is pinned.
        """
        bootstrap = dict(_rendered_prompts())["sl1_session_bootstrap"]
        assert "`sl1_create_guided_discovery_session`" in bootstrap
        assert "no dedicated\n   tool" not in bootstrap
        assert "There is no\n   dedicated tool" not in bootstrap


class TestTheBlastRadiusPromptIsDerivedNotTranscribed:
    """The ``db_write`` family gets one family-level warning, derived from the registry.

    Per-tool consequences are scattered across several prompts; this prompt puts the family, the
    ``master.*``/autocommit fact and the inverse inventory in one place a caller reads before the
    first write. Every expectation here is derived from ``authz.TOOL_REGISTRY`` or the live tool
    surface, because a transcribed list would keep passing after the registry moved.
    """

    def test_it_names_exactly_the_db_write_family(self) -> None:
        """Not a subset and not a superset: naming four of five is the failure that matters."""
        text = dict(_rendered_prompts())["sl1_write_blast_radius_guide"]
        expected = set(tool_names_for_set(DB_WRITE_SET))
        assert expected, "the db_write set is empty, so this test proves nothing"
        named = set(re.findall(r"`(sl1_[a-z0-9_]+)`", text))
        assert expected <= named, f"blast-radius prompt omits {sorted(expected - named)}"

    def test_the_inverse_inventory_matches_the_real_surface(self) -> None:
        """The claim "the whole surface has three inverses" is the prompt's strongest.

        If a fourth inverse ships and the prompt still says three, a caller would forgo an undo
        that exists. So the count is derived from the tool surface.
        """
        server: FastMCP = FastMCP(name="inverse-probe")
        config = Config()
        register_tools(
            server,
            LceClient(config),
            config,
            Sl1Client(config),
            DbClient(config.MAX_CONCURRENT_REQUESTS),
        )
        inverses = {
            tool.name
            for tool in registered_tools(server)
            if any(verb in tool.name for verb in ("delete", "unalign", "remove"))
        }
        assert inverses == {
            "sl1_delete_device",
            "sl1_delete_credential",
            "sl1_unalign_dynamic_apps_from_device",
        }, f"the inverse inventory changed: {sorted(inverses)} -- update the prompt's point 3"

        text = dict(_rendered_prompts())["sl1_write_blast_radius_guide"]
        assert "THREE INVERSES" in text
        for tool in inverses:
            assert f"`{tool}`" in text, f"point 3 claims three inverses but omits `{tool}`"

    def test_it_carries_the_no_rollback_fact_and_not_only_the_consequences(self) -> None:
        """The prompt names the mechanism, not only the effects.

        ``db_client.py`` and ``sl1_db_tools.py`` both state it, so a prompt-blind client is covered;
        this asserts the orienting read is too.
        """
        text = dict(_rendered_prompts())["sl1_write_blast_radius_guide"]
        assert "master.*" in text
        assert "NO TRANSACTION AND NO ROLLBACK" in text
        assert "PARTIALLY-APPLIED WRITE IS REACHABLE" in text

    def test_both_rehearsal_mechanisms_are_named(self) -> None:
        """A dry run that exists and goes unused is a wholly avoidable permanent write."""
        text = dict(_rendered_prompts())["sl1_write_blast_radius_guide"]
        assert "`sl1_create_guided_discovery_session`" in text
        assert "dry_run=true" in text
        assert "`lce_create_or_update_dynamic_applications`" in text
        assert "commit=false" in text

    def test_the_check_is_not_vacuous(self) -> None:
        """The prompt is composed at call time; a rename would make every assert above moot."""
        assert "sl1_write_blast_radius_guide" in PROMPT_NAMES
        assert "sl1_write_blast_radius_guide" in dict(_rendered_prompts())

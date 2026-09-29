"""
Content Standards Catalog

This module provides the PowerPack content-standards catalog: every Pleco rule, enforced and not
yet enforced, as a static in-memory constant. Nothing is read, cached or fetched at call time.
``RULES`` is baked at build time and ``CATALOG_SOURCE`` records where it came from.

The rule text is transcribed by script from Pleco's ``pp_standards_tests`` so it cannot drift in
transcription. ``entity`` is an open ``str`` rather than an enum, so a new upstream entity type
arrives as a catalog edit rather than a code change; a closed enum written from a stale list would
silently drop rules. Pleco's lint implementations are not ported, because they would duplicate
and conflict with the deliberately narrow checks in ``validation.py``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

__all__ = ["CATALOG_SOURCE", "KNOWN_ENTITIES", "RULES", "ContentStandardRule"]


@dataclass(frozen=True, slots=True)
class ContentStandardRule:
    """One content-standards rule.

    Pleco's source calls ``name`` ``id`` and ``linted_in_loop`` ``lints_here``;
    ``get_content_standards`` returns the names used here.

    :ivar name: The Pleco test function name. A stable identifier, so drift is diffable.
    :ivar entity: One of ``KNOWN_ENTITIES``. An open ``str``, not an enum.
    :ivar enforced: ``True`` if Pleco enforces this rule today; ``False`` for a documented
        convention not yet enforced upstream.
    :ivar linted_in_loop: ``True`` if this service also checks the rule, so a caller can tell
        rules verified here from those only Pleco enforces at build time.
    :ivar text: The one-line statement of the rule.
    """

    name: str
    entity: str
    enforced: bool
    linted_in_loop: bool
    text: str


# Provenance. With no refresh tool this is the only signal that the catalog may have drifted from
# upstream, so it travels with every response. Unlike the rules, ``note`` is written for this
# build: Pleco's version points callers at ``refresh_content_standards``, which this server does
# not have.
CATALOG_SOURCE: Final[dict[str, str]] = {
    "tool": "Pleco / PowerPack Quality Tool (PQT)",
    "repo": "PowerPacks/pp_standards_tests",
    "ref": "main",
    "synced": "2026-07-13",
    "gate": "Pleco, run per build in CI",
    "note": (
        "Pleco is the authoritative gate; this catalog is the in-loop mirror, baked at build time. "
        "This build ships NO drift-check: refresh_content_standards is not included in this build, "
        "because it requires the gh CLI authenticated over VPN to GitHub Enterprise and gh is not "
        "expected on an appliance. Compare the synced date against pp_standards_tests to judge "
        "staleness. Re-entry condition: re-implement the drift-check over httpx against the GHE "
        "API, "
        "bringing it inside this service's own client and error taxonomy."
    ),
}

# The entity types present in ``RULES``. Documentation, not validation: an unrecognised entity
# returns an empty list rather than an error, so nothing rejects a value for being absent here.
KNOWN_ENTITIES: Final[tuple[str, ...]] = (
    "alert",
    "collection_object",
    "device_category",
    "dynamic_application",
    "event_policy",
    "powerpack",
    "presentation_object",
)

# Baked from pp_standards_tests @ CATALOG_SOURCE["synced"]: ALL rules, enforced and not-yet-enforced
# alike, so the tool answers fully offline. Grouped by entity, with counts, so a dropped rule is
# visible in review rather than only in a test failure.
RULES: Final[tuple[ContentStandardRule, ...]] = (
    # ---- alert (14) ----
    ContentStandardRule(
        "test_da_alert_event",
        "alert",
        True,
        False,
        "All alerts have a corresponding event.",
    ),
    ContentStandardRule(
        "test_da_alerts_zero",
        "alert",
        True,
        True,
        (
            "This rule checks that an alert formula does not divide by 0. If a formula has a "
            "division, ensure that it will not divide by zero by examples such as: * `o_id !=."
        ),
    ),
    ContentStandardRule(
        "test_da_alerts_alertformat",
        "alert",
        False,
        False,
        (
            "Internal Alert messages should follow this template: 'Application_name [App_ID]: "
            "Alert messages'."
        ),
    ),
    ContentStandardRule(
        "test_da_alerts_clear_alert",
        "alert",
        False,
        False,
        (
            '"return to normal" formula should include "and active(<error_threshold_id>)" for each '
            "policy that triggered the non-normal condition."
        ),
    ),
    ContentStandardRule(
        "test_da_alerts_greaterthan",
        "alert",
        False,
        False,
        'use ">" when exceeding a threshold.',
    ),
    ContentStandardRule(
        "test_da_alerts_greaterthanorequal",
        "alert",
        False,
        False,
        'use ">=" when returning from a low threshold.',
    ),
    ContentStandardRule(
        "test_da_alerts_lessthan",
        "alert",
        False,
        False,
        'use "<" when falling through a lower-bound threshold.',
    ),
    ContentStandardRule(
        "test_da_alerts_lessthanorequal",
        "alert",
        False,
        False,
        'use "<=" when returning to normal from high threshold.',
    ),
    ContentStandardRule(
        "test_da_alerts_logmessage",
        "alert",
        False,
        False,
        'include "%L" in the Log Message if data is non-scalar.',
    ),
    ContentStandardRule(
        "test_da_alerts_logmessage_parentheses",
        "alert",
        False,
        True,
        'if "%L" occurs in the Log Message it must be wrapped in parentheses.',
    ),
    ContentStandardRule(
        "test_da_alerts_maintain_state",
        "alert",
        False,
        False,
        "set 'maintain state' to Yes, when exceeding a threshold.",
    ),
    ContentStandardRule(
        "test_da_alerts_round",
        "alert",
        False,
        False,
        "if collection object is a float, alert must round to two decimal places.",
    ),
    ContentStandardRule(
        "test_da_alerts_units",
        "alert",
        False,
        True,
        (
            '"%T" and "%V" in alerts must be followed by units that match the threshold and '
            "presentation object units."
        ),
    ),
    ContentStandardRule(
        "test_da_alerts_vendor",
        "alert",
        False,
        False,
        "include vendor name in Alert policy, if any.",
    ),
    # ---- collection_object (1) ----
    ContentStandardRule(
        "test_empty_cobj_descriptions",
        "collection_object",
        True,
        True,
        (
            "Test for empty collection object descriptions. The validation is not taking into "
            "account collection objects that have the class-type as Label or Discovery."
        ),
    ),
    # ---- device_category (4) ----
    ContentStandardRule(
        "test_device_categories_singular",
        "device_category",
        False,
        False,
        "Device categories must use the singular form of words.",
    ),
    ContentStandardRule(
        "test_device_categories_system_group",
        "device_category",
        False,
        False,
        "System group of categories is reserved for ScienceLogic products.",
    ),
    ContentStandardRule(
        "test_device_categories_valid_values",
        "device_category",
        False,
        False,
        (
            "If you need to add a device class, pick the device category that best matches your "
            "device class from the approved list below. A device class must be in on."
        ),
    ),
    ContentStandardRule(
        "test_device_categories_vendor_names",
        "device_category",
        False,
        False,
        "Device categories must not include vendor names.",
    ),
    # ---- dynamic_application (23) ----
    ContentStandardRule(
        "test_da_format_in_description",
        "dynamic_application",
        True,
        True,
        (
            'Do not abbreviate "Dynamic Application" or use lowercase. Use the full phrase '
            "everywhere with both words capitalized. Also checks to make sure that the Dynamic."
        ),
    ),
    ContentStandardRule(
        "test_da_format_in_release_notes",
        "dynamic_application",
        True,
        True,
        (
            'Do not abbreviate "Dynamic Application" or use lowercase. Use the full phrase '
            "everywhere with both words capitalized. Also checks to make sure that the Dynamic."
        ),
    ),
    ContentStandardRule(
        "test_da_naming_spaces",
        "dynamic_application",
        True,
        True,
        "Dynamic Application can not have multiple spaces in the name.",
    ),
    ContentStandardRule(
        "test_da_release_notes_has_copyright_info",
        "dynamic_application",
        True,
        True,
        (
            "Validates Dynamic Application release notes contain a valid copyright. Release Notes: "
            "copyright section is at the bottom and contains an updated copy of company."
        ),
    ),
    ContentStandardRule(
        "test_da_releasenotes_line",
        "dynamic_application",
        True,
        True,
        "Release Notes: horizontal line preceeds the copyright.",
    ),
    ContentStandardRule(
        "test_da_releasenotes_updatelist",
        "dynamic_application",
        True,
        True,
        "Validate that the release notes contain an update list in Numbered-List format.",
    ),
    ContentStandardRule(
        "test_da_releasenotes_version",
        "dynamic_application",
        True,
        True,
        (
            "Validates that the latest version in the release notes matches the version of Dynamic "
            "Application."
        ),
    ),
    ContentStandardRule(
        "test_da_releasenotes_versionbold",
        "dynamic_application",
        True,
        True,
        (
            "Validates that each release section of the Release Notes contains a version number "
            "that is bold."
        ),
    ),
    ContentStandardRule(
        "test_da_threshold_high",
        "dynamic_application",
        True,
        True,
        "Validates that a threshold high is numerically 100 when threshold is a percentage.",
    ),
    ContentStandardRule(
        "test_da_threshold_low",
        "dynamic_application",
        True,
        True,
        "Validates that a threshold low is numerically 0 when threshold is a percentage.",
    ),
    ContentStandardRule(
        "test_da_thresholds_required",
        "dynamic_application",
        True,
        False,
        (
            "Verify that if an alert formula exists which includes a threshold, that a threshold "
            "object also exists. Create a threshold whenever a value in an alert is check."
        ),
    ),
    ContentStandardRule(
        "test_da_thresholds_thresholds_units_format",
        "dynamic_application",
        True,
        True,
        (
            "Threshold unit is not empty. If the threshold is not a percentage and each word is "
            "capitalized or special."
        ),
    ),
    ContentStandardRule(
        "test_config_da_poll_freq_change",
        "dynamic_application",
        False,
        False,
        (
            "Config apps data collection poll between: 1 to 1440 minutes and at-least one "
            "collection object must have change alerting enabled."
        ),
    ),
    ContentStandardRule(
        "test_da_naming_purpose",
        "dynamic_application",
        False,
        False,
        (
            'Each "Dynamic Application" is appended with one of several valid tags indicating '
            "purpose: Discovery, Configuration, Performance, Count (are there more?). This r."
        ),
    ),
    ContentStandardRule(
        "test_da_poll_frequency",
        "dynamic_application",
        False,
        False,
        "Performance Data collection: 5 to 15 minutes. Config apps poll between 1 and 1440 mins.",
    ),
    ContentStandardRule(
        "test_da_pollfrequency_journal",
        "dynamic_application",
        False,
        False,
        "Journal applications have no guidelines on polling frequency.",
    ),
    ContentStandardRule(
        "test_da_releasenotes_topupdate",
        "dynamic_application",
        False,
        False,
        "Release Notes and Change Log: new release is at the top.",
    ),
    ContentStandardRule(
        "test_da_snippets_logfile",
        "dynamic_application",
        False,
        False,
        "do not write any log information to /data/tmp.",
    ),
    ContentStandardRule(
        "test_da_thresholds_name_format",
        "dynamic_application",
        False,
        False,
        'thresholds name format is "<entity><metric><level>".',
    ),
    ContentStandardRule(
        "test_da_version_beta_increment",
        "dynamic_application",
        False,
        False,
        "Beta dynamic apps will increment by 0.1 for each new release.",
    ),
    ContentStandardRule(
        "test_da_version_beta_initial",
        "dynamic_application",
        False,
        False,
        (
            "Initial versions of Beta dynamic app will have version of 0.5, regardless of when "
            "they are inroduced and GA powerpacks will take on the values of 1.0 or l."
        ),
    ),
    ContentStandardRule(
        "test_da_version_ga_increment",
        "dynamic_application",
        False,
        False,
        "GA dynamic apps will increment version by 0.1 for each new release.",
    ),
    ContentStandardRule(
        "test_da_version_ga_initial",
        "dynamic_application",
        False,
        False,
        "initial GA dynamic app will have version of 1.0.",
    ),
    # ---- event_policy (8) ----
    ContentStandardRule(
        "test_event_advanced_expiry_delays",
        "event_policy",
        True,
        True,
        (
            "Checks if the expiry delays conforms with the standards. expiry delays: healthy=15 "
            "(minutes), notice=30, minor=60, major=90, critical=90 eseverity: '0'=healthy,."
        ),
    ),
    ContentStandardRule(
        "test_event_policies_description_format",
        "event_policy",
        True,
        True,
        (
            "Event policy description should contain three sections in this order: Description, "
            "Probable Cause, and Resolution The format should match the regex provided in."
        ),
    ),
    ContentStandardRule(
        "test_event_policies_severity",
        "event_policy",
        True,
        True,
        (
            "Checks if the severity conforms with the standards. Event severity must be one of "
            "these: Healthy(0), Notice(1), Minor(2), Major(3), Critical(4)."
        ),
    ),
    ContentStandardRule(
        "test_event_policies_state",
        "event_policy",
        True,
        True,
        "Checks if event policy state is enabled. operational state='1' (enabled).",
    ),
    ContentStandardRule(
        "test_event_policies_description",
        "event_policy",
        False,
        False,
        (
            "policy Description must contain these headers in order and in bold: Description, "
            "Probable Cause, Resolution."
        ),
    ),
    ContentStandardRule(
        "test_event_policies_format",
        "event_policy",
        False,
        False,
        (
            'Event policy format: "<Vendor>:<Application/Component><Version><has exceeded '
            'threshold | returned to Normal | fell below the threshold>".'
        ),
    ),
    ContentStandardRule(
        "test_event_policies_substitute",
        "event_policy",
        False,
        False,
        'event message is "%M" when the value of the string gets set elsewhere.',
    ),
    ContentStandardRule(
        "test_event_policies_vendor_terminology",
        "event_policy",
        False,
        False,
        "use vendor terminology for all policy Description fields.",
    ),
    # ---- powerpack (32) ----
    ContentStandardRule(
        "test_powerpack_word_is_not_in_pp_name",
        "powerpack",
        True,
        False,
        (
            "Validate that *PowerPack* in any form does not appear in the name. Not allowed: "
            "PowerPack, powerpack, Power-Pack, Powerpack, Power-pack."
        ),
    ),
    ContentStandardRule(
        "test_pp_credential_example",
        "powerpack",
        True,
        False,
        "PowerPack includes an example credential marked as *Example*.",
    ),
    ContentStandardRule(
        "test_pp_description",
        "powerpack",
        True,
        False,
        (
            "PowerPack description is a fully-formed sentence. Description must have "
            "capitalization and a period, may not be blank."
        ),
    ),
    ContentStandardRule(
        "test_pp_library_uniqueness",
        "powerpack",
        True,
        False,
        (
            "Validate the content library's uniqueness. Based on the content library's names that "
            "are part of a powerpack, we can see if the content library is or is not dup."
        ),
    ),
    ContentStandardRule(
        "test_pp_models_empty",
        "powerpack",
        True,
        False,
        "The *models* field is not empty.",
    ),
    ContentStandardRule(
        "test_pp_name",
        "powerpack",
        True,
        False,
        (
            'Validate the name of the PowerPack. Base packs should look like: "Vendor Base Pack", '
            'without a colon. Non-base packs should look like: "Vendor: Product". Genera.'
        ),
    ),
    ContentStandardRule(
        "test_pp_name_has_special_characters",
        "powerpack",
        True,
        False,
        (
            "PowerPack name does not include parentheses or special characters. Only colon, "
            "underscore, and dash are allowed."
        ),
    ),
    ContentStandardRule(
        "test_pp_publisher",
        "powerpack",
        True,
        False,
        "Validate the publisher field contains exactly *ScienceLogic, Inc.*.",
    ),
    ContentStandardRule(
        "test_pp_releasenotes_copyright",
        "powerpack",
        True,
        False,
        "Release Notes: horizontal line precedes the copyright and the copyright year is current.",
    ),
    ContentStandardRule(
        "test_pp_vendors_empty",
        "powerpack",
        True,
        False,
        "The *vendors* field is not empty.",
    ),
    ContentStandardRule(
        "test_pp_version_valid",
        "powerpack",
        True,
        False,
        (
            "Validate the PowerPack version. A valid version is a positive integer (new style), or "
            "dotted *major.minor.revision* string (old style)."
        ),
    ),
    ContentStandardRule(
        "test_pp_credentials_requiredfields",
        "powerpack",
        False,
        False,
        "Example credential will have all required fields filled out with instructional text.",
    ),
    ContentStandardRule(
        "test_pp_finalprep_administrative_key",
        "powerpack",
        False,
        False,
        "administrative key embedded.",
    ),
    ContentStandardRule(
        "test_pp_finalprep_extraneous_objects",
        "powerpack",
        False,
        False,
        (
            "No extraneous objects appear in the PP (objects from a different PP accidentally "
            "included)."
        ),
    ),
    ContentStandardRule(
        "test_pp_finalprep_vendors",
        "powerpack",
        False,
        False,
        (
            "vendor(s), model(s), and version(s) supported by the PP. If applicable, the "
            "vendor(s), model(s), and version(s) that the PowerPack will support."
        ),
    ),
    ContentStandardRule(
        "test_pp_forceremove",
        "powerpack",
        False,
        False,
        (
            "Ensure use of force_remove for any object being removed from previous version. Two "
            "important notes on force_remove -."
        ),
    ),
    ContentStandardRule(
        "test_pp_releasenotes_update",
        "powerpack",
        False,
        False,
        "Release Notes and Change Log is non-blank and new release is at the top.",
    ),
    ContentStandardRule(
        "test_pp_releasenotes_updatelist",
        "powerpack",
        False,
        False,
        (
            "New release section of Release Notes: contains numbered list of updates. The "
            "Description of each update in a numbered list. Any additional release notes t."
        ),
    ),
    ContentStandardRule(
        "test_pp_releasenotes_version",
        "powerpack",
        False,
        False,
        "New release section of Release Notes: Version number matches version of PP.",
    ),
    ContentStandardRule(
        "test_pp_releasenotes_versionbold",
        "powerpack",
        False,
        False,
        "New release section of Release Notes: Version number is in bold.",
    ),
    ContentStandardRule(
        "test_pp_technicalnotes_table",
        "powerpack",
        False,
        False,
        "Technical Notes contains non-blank table mapping PP version to EM7 version.",
    ),
    ContentStandardRule(
        "test_pp_technicalnotes_update",
        "powerpack",
        False,
        False,
        "New release in Technical Notes is at the top.",
    ),
    ContentStandardRule(
        "test_pp_technicalnotes_version",
        "powerpack",
        False,
        False,
        (
            "Version number of new release in Technical Notes matches version of PP. This test "
            "makes sure that the version number of the PowerPack is the same as what."
        ),
    ),
    ContentStandardRule(
        "test_pp_version_alpha",
        "powerpack",
        False,
        False,
        (
            "Alpha powerpacks initial version number is 0.1 and will not be checked into source "
            "control."
        ),
    ),
    ContentStandardRule(
        "test_pp_version_beta1",
        "powerpack",
        False,
        False,
        "Beta version number is less than one. Remember, a version gte 0.9 or eq. Not production.",
    ),
    ContentStandardRule(
        "test_pp_version_beta2",
        "powerpack",
        False,
        False,
        "Initial release for a Beta version number is 0.5.",
    ),
    ContentStandardRule(
        "test_pp_version_dynamicapp",
        "powerpack",
        False,
        False,
        "No correlation between PP version and Dynamic App version.",
    ),
    ContentStandardRule(
        "test_pp_version_em7version",
        "powerpack",
        False,
        False,
        "PowerPack version numbers are independent of EM7 version.",
    ),
    ContentStandardRule(
        "test_pp_version_ga",
        "powerpack",
        False,
        False,
        "Initial Version number is 1.0.",
    ),
    ContentStandardRule(
        "test_pp_version_increment1",
        "powerpack",
        False,
        False,
        (
            "Increment version number by at least 0.1 from previous version number. Version "
            "numbers should be incremented for each major change that is committed to th."
        ),
    ),
    ContentStandardRule(
        "test_pp_version_increment2",
        "powerpack",
        False,
        False,
        "TBD - 1107.",
    ),
    ContentStandardRule(
        "test_pp_versions_empty",
        "powerpack",
        False,
        False,
        "The *versions* field is not empty.",
    ),
    # ---- presentation_object (11) ----
    ContentStandardRule(
        "test_da_po_data_units",
        "presentation_object",
        True,
        True,
        (
            "Presentation object unit is correct based on units.json file. Set the data unit as a "
            "readable string."
        ),
    ),
    ContentStandardRule(
        "test_da_po_data_units_format",
        "presentation_object",
        True,
        True,
        "Presentation object unit's each word is capitalized or unit is empty.",
    ),
    ContentStandardRule(
        "test_da_po_formula_rounding_precision",
        "presentation_object",
        True,
        True,
        (
            "Verify rounding precision in presentation object where applicable. If any rounding "
            "needs to be done the final result should have a precision of 2. Therefore for."
        ),
    ),
    ContentStandardRule(
        "test_da_po_suffix",
        "presentation_object",
        True,
        True,
        "Use an industry standard abbreviation for the Abbreviation/Suffix fields when available.",
    ),
    ContentStandardRule(
        "test_empty_guide_text_presentation_objects",
        "presentation_object",
        True,
        True,
        "Test for empty presentation object guide text.",
    ),
    ContentStandardRule(
        "test_summarization_state_enabled",
        "presentation_object",
        True,
        True,
        (
            "Add validation to ensure that Presentation Objects have enabled the Summarization "
            'State (i.e. has set "state" to 1).'
        ),
    ),
    ContentStandardRule(
        "test_da_po_dataunit_seconds",
        "presentation_object",
        False,
        False,
        'Data unit abbreviation for seconds should be "s". (This rule enables autoscaling.).',
    ),
    ContentStandardRule(
        "test_da_po_formula_range",
        "presentation_object",
        False,
        False,
        "formulas: range checks where applicable.",
    ),
    ContentStandardRule(
        "test_da_po_formula_rounding",
        "presentation_object",
        False,
        False,
        (
            "perform rounding in presentation object where applicable. If any rounding needs to be "
            "done, it is done in the presentation object formula, rather than in."
        ),
    ),
    ContentStandardRule(
        "test_da_po_iops",
        "presentation_object",
        False,
        False,
        (
            "Add support for the Storage standards for the operations per second metrics. The Data "
            "Unit should be IOs/Second and Abbreviation/Suffix should be set to I."
        ),
    ),
    ContentStandardRule(
        "test_da_po_name",
        "presentation_object",
        False,
        False,
        "set the name so that it concisely describes the presentation.",
    ),
)

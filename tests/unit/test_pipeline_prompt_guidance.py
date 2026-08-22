"""The pipeline instruction must tell the model WHEN to act and WHICH action.

CRM-238: the previous wording was two prohibitions in a row ("apply a rule only
when…", "do not move conversations between stages without…") with no positive
criterion, and never said whether the conversation already had a card. In live
runs the model either did nothing at all, or picked add_to_pipeline for a
conversation that was already in the funnel (400 CONVERSATION_NOT_FOUND).

It also told the model the ids were automatic while the tool schema offered
them as parameters — so the model filled conversation_id with the CONTACT id.
"""

from src.services.adk.tools.evo_crm.pipeline_manipulation import create_pipeline_manipulation_tool
from src.services.adk.agents.llm_agent_builder import _pipeline_tool_instruction

# The RENDERED text, not the source: reading the source made the assertions
# depend on where Python string concatenation happened to break the line.
PROMPT_BLOCK = _pipeline_tool_instruction([
    "- Pipeline: Vendas (pipeline_id: pipe-1)",
    "    - Stage: Fechado (stage_id: stg-fechado) — move here when: quando confirma a compra",
])


class TestPositiveCriterion:
    def test_says_when_to_act(self):
        assert "WHEN TO ACT" in PROMPT_BLOCK

    def test_acting_is_expected_not_merely_permitted(self):
        # The regression: only prohibitions made the model sit still.
        assert "Acting is expected" in PROMPT_BLOCK

    def test_does_not_require_the_customer_to_ask(self):
        assert "do not wait for the customer to ask" in PROMPT_BLOCK

    def test_still_forbids_inventing_a_stage(self):
        # Guardrail kept: the fix must not turn into "move anywhere".
        assert "never invent a stage" in PROMPT_BLOCK
        assert "leave the card where it is" in PROMPT_BLOCK


class TestActionChoice:
    def test_explains_move_vs_add(self):
        assert "move_to_stage" in PROMPT_BLOCK
        assert "add_to_pipeline" in PROMPT_BLOCK

    def test_move_is_the_normal_case_for_an_ongoing_conversation(self):
        assert "already has a card" in PROMPT_BLOCK
        assert "not in any pipeline yet" in PROMPT_BLOCK


class TestIdsAreNotTheModelsToFill:
    def test_prompt_tells_the_model_not_to_set_them(self):
        assert "do NOT set conversation_id or contact_id" in PROMPT_BLOCK

    def test_prompt_says_what_the_model_SHOULD_provide(self):
        assert "Provide pipeline_id and stage_id" in PROMPT_BLOCK

    def test_tool_schema_agrees_with_the_prompt(self):
        """The contradiction that caused CRM-237: schema offered what the prompt
        called automatic."""
        doc = create_pipeline_manipulation_tool().func.__doc__

        assert "DO NOT SET" in doc
        # The old text promised automatic extraction while inviting a value.
        assert "conversation_id: ID of the conversation (optional" not in doc

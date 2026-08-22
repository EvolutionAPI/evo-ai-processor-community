"""The agent's pipeline rules must reach the model with their STAGES.

The frontend saves (PipelineRules.tsx):

    PipelineRule { pipelineId, pipelineName, generalInstructions, stages: StageRule[] }
    StageRule    { stageId, stageName, instructions }

The prompt builder used to read ``stageName``/``instructions`` off the RULE,
where they do not exist, so a fully configured funnel rendered as a single
line with the funnel name. Since the same prompt tells the model "do not move
conversations between stages without a matching rule", the model had nothing
to match and never moved the card — the reported "the AI freezes and does not
execute". ``pipeline_manipulation`` always read ``rule["stages"]`` correctly;
only the prompt side was wrong.

These tests pin the contract on the side that was broken, using the exact
shape the UI writes.
"""

from src.services.adk.agents.llm_agent_builder import _format_pipeline_rules_for_prompt


def _real_ui_rules():
    """Exactly what PipelineRulesModal persists for a two-stage funnel."""
    return [
        {
            "id": "rule-1",
            "pipelineId": "pipe-1",
            "pipelineName": "Vendas",
            "allowTasks": True,
            "allowServices": False,
            "generalInstructions": "Funil principal de vendas",
            "stages": [
                {
                    "id": "s1",
                    "stageId": "stg-qualificado",
                    "stageName": "Qualificado",
                    "instructions": "quando o lead confirma interesse no produto",
                },
                {
                    "id": "s2",
                    "stageId": "stg-fechado",
                    "stageName": "Fechado",
                    "instructions": "quando o lead confirma a compra",
                },
            ],
        }
    ]


class TestPipelineRulesReachTheModel:
    def test_every_configured_stage_appears(self):
        text = "\n".join(_format_pipeline_rules_for_prompt(_real_ui_rules()))

        assert "Qualificado" in text
        assert "Fechado" in text

    def test_stage_ids_are_exposed_so_the_tool_can_be_called(self):
        # Without the id the model can only guess a name, and
        # pipeline_manipulation answers "stage_id or stage_name is required".
        text = "\n".join(_format_pipeline_rules_for_prompt(_real_ui_rules()))

        assert "stg-qualificado" in text
        assert "stg-fechado" in text
        assert "pipe-1" in text

    def test_per_stage_instructions_are_the_when_to_move(self):
        text = "\n".join(_format_pipeline_rules_for_prompt(_real_ui_rules()))

        assert "quando o lead confirma interesse no produto" in text
        assert "quando o lead confirma a compra" in text

    def test_general_instructions_are_kept(self):
        text = "\n".join(_format_pipeline_rules_for_prompt(_real_ui_rules()))

        assert "Funil principal de vendas" in text

    def test_a_configured_funnel_never_renders_as_a_bare_name(self):
        """The regression itself: one line, funnel name only."""
        lines = _format_pipeline_rules_for_prompt(_real_ui_rules())

        assert len(lines) > 1, f"stages were dropped from the prompt: {lines!r}"


class TestEdgeShapes:
    def test_legacy_flat_rule_still_renders(self):
        # A config written by an older UI kept the stage on the rule itself.
        legacy = [
            {
                "pipelineId": "pipe-9",
                "pipelineName": "Antigo",
                "stageName": "Ganho",
                "instructions": "quando fechar",
            }
        ]

        text = "\n".join(_format_pipeline_rules_for_prompt(legacy))

        assert "Ganho" in text
        assert "quando fechar" in text

    def test_rule_without_stages_still_names_the_pipeline(self):
        text = "\n".join(_format_pipeline_rules_for_prompt([{"pipelineId": "p", "pipelineName": "Só o funil"}]))

        assert "Só o funil" in text

    def test_garbage_entries_do_not_raise(self):
        assert _format_pipeline_rules_for_prompt([]) == []
        assert _format_pipeline_rules_for_prompt(None) == []
        assert _format_pipeline_rules_for_prompt(["not a dict", 42]) == []

        out = _format_pipeline_rules_for_prompt([{"pipelineName": "X", "stages": ["bad", None]}])
        assert any("X" in line for line in out)

"""Capstone facades: whole pipelines behind one call.

``BinaryToRule`` wires Exp 2 end to end (static extraction -> candidates ->
pooling -> ISB-A -> budget -> ISB-B -> rule) so a caller -- the threat-hunt
agent, a notebook, a demo -- needs no knowledge of the stages.

Replaces the former ``RuleGeneratorIOC`` stub, which imported a
``YaraGen.Models`` module that does not exist in this repository.
"""

from .BinaryToRule import BinaryToRule, BinaryToRuleConfig

__all__ = ["BinaryToRule", "BinaryToRuleConfig"]

"""Detection evaluation: rules x corpora -> TPR, FP/1k, explicit failures.

FP is a **goodware-only** metric. Cross-family matches and vault matches are
malware-on-malware and are reported in their own columns (EXP2_DESIGN §10/§10b);
folding either into FP would let a rule that detects all malware look precise.
"""

from .harness import DetectionConfig, DetectionHarness, RuleUnit, ScanTarget

__all__ = ["DetectionHarness", "DetectionConfig", "RuleUnit", "ScanTarget"]

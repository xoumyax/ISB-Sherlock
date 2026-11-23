"""Import shim for the V1 reference code; not part of V1.

V1's modules and tests import ``YaraGen.ISB``. This file makes ``legacy/V1``
a root that provides exactly that package and nothing else from the YaraGen
research code base. ``tests/legacy/conftest.py`` puts ``legacy/V1`` first on
``sys.path`` and checks that ``YaraGen.ISB`` resolves here.
"""

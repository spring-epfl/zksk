import os
import sys
import importlib

import pytest

PACKAGE_NAME = "zksk"
EXAMPLES_MOD = "examples"
BASE_PATH = dir_path = os.path.dirname(os.path.realpath(__file__))
EXAMPLES_DIR = os.path.join(BASE_PATH, "..", EXAMPLES_MOD)
EXAMPLE_MODULE_NAMES = [f[:-3] for f in os.listdir(EXAMPLES_DIR) if f.endswith(".py")]


@pytest.mark.parametrize("mod", EXAMPLE_MODULE_NAMES)
def test_examples(mod):
    importlib.import_module("%s.%s" % (EXAMPLES_MOD, mod), PACKAGE_NAME)

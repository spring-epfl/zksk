__version__ = "0.0.2"
__title__ = "zksk"
__author__ = "Wouter Lueks, Bogdan Kulynych, Jules Fasquelle, Simon Le Bail-Collet"
__email__ = "wouter.lueks@epfl.ch"
__url__ = "https://zksk.readthedocs.io"
__license__ = "MIT"
__description__ = "Zero-Knowledge Swiss Knife: Python library for prototyping composable zero-knowledge proofs."
__copyright__ = "2020, Wouter Lueks, Bogdan Kulynych (EPFL SPRING Lab)"


from zksk.expr import Secret
from zksk.primitives.dlrep import DLRep
from zksk.utils import make_generators

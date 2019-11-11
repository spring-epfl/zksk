####
zksk
####

|build_status| |docs_status| |coverage| |license| |arxiv|

.. |build_status| image:: https://travis-ci.org/spring-epfl/zksk.svg?branch=master
   :target: https://travis-ci.org/spring-epfl/zksk
   :alt: Build status

.. |docs_status| image:: https://readthedocs.org/projects/zksk/badge/?version=latest
   :target: https://zksk.readthedocs.io/?badge=latest
   :alt: Documentation status

.. |coverage| image:: https://codecov.io/gh/spring-epfl/zksk/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/spring-epfl/zksk
   :alt: Test coverage

.. |license| image:: https://img.shields.io/badge/License-MIT-yellow.svg
   :target: https://opensource.org/licenses/MIT
   :alt: MIT License

.. |arxiv| image:: https://img.shields.io/badge/cs.CR-arXiv%3A1911.02459-red
   :target: https://arxiv.org/abs/1911.02459
   :alt: Paper on arXiv

.. start-description-marker-do-not-remove

Zero-Knowledge Swiss Knife: Python library for prototyping composable zero-knowledge proofs in the
discrete-log setting.

--------------------------------------------------------------------------------------------------

Let's say Peggy commits to a secret bit and wants to prove to Victor in zero knowledge that she
knows this bit—that is, without revealing it. In Camenisch-Stadler notation, we can write:

.. image:: https://raw.githubusercontent.com/spring-epfl/zksk/master/images/bit_proof_stmt.svg?sanitize=true
   :alt: PK{ (r): (C = rH) ∨ (C - G = rH) }

To implement this zero-knowledge proof, Peggy will run:

.. code-block:: python

    from zksk import Secret, DLRep
    from zksk import utils

    # Setup: Peggy and Victor agree on two group generators.
    G, H = utils.make_generators(num=2, seed=42)
    # Setup: generate a secret randomizer.
    r = Secret(utils.get_random_num(bits=128))

    # This is Peggy's secret bit.
    top_secret_bit = 1

    # A Pedersen commitment to the secret bit.
    C = top_secret_bit * G + r.value * H

    # Peggy's definition of the proof statement, and proof generation.
    # (The first or-clause corresponds to the secret value 0, and the second to the value 1. Because
    # the real value of the bit is 1, the clause that corresponds to zero is marked as simulated.)
    stmt = DLRep(C, r * H, simulated=True) | DLRep(C - G, r * H)
    zk_proof = stmt.prove()


Victor will receive the commitment ``C`` and ``zk_proof`` from Peggy, and run this to verify the
proof:

.. code-block:: python

    from zksk import Secret, DLRep

    # Setup: get the agreed group generators.
    G, H = utils.make_generators(num=2, seed=42)
    # Setup: define a randomizer with an unknown value.
    r = Secret()

    stmt = DLRep(C, r * H) | DLRep(C - G, r * H)
    assert stmt.verify(zk_proof)

Victor is now convinced that Peggy knows the committed bit.

--------------------------------------------------------------------------------------------

===========================
Documentation and materials
===========================

+----------------+--------------------------------------------------------------------+
| Docs           | https://zksk.readthedocs.io                                        |
+----------------+--------------------------------------------------------------------+
| Academic paper | https://arxiv.org/abs/1911.02459 —                                 |
|                | theoretical details                                                |
+----------------+--------------------------------------------------------------------+

.. end-description-marker-do-not-remove

> **Warning.** Please don't use this software for anything mission-critical. It is designed for
quick protyping of privacy-enhancing technologies, not production use.

--------------------------------------------------------------------------------------------


===============
Getting started
===============

.. start-getting-started-marker-do-not-remove

You need to have Python 3.6 or higher to use zksk. The library is tested and supported on
Debian-based systems. Mac support is not guaranteed.

You can install zksk using pip:

.. code-block:: bash

   pip install git+https://github.com/spring-epfl/zksk

To make sure everything is in order, you can run unit tests. For that, install the dev version of
the package:

.. code-block:: bash

   pip install "git+https://github.com/spring-epfl/zksk#egg=zksk[dev]"

Then, run the tests with pytest:

.. code-block:: bash

   pytest

.. end-getting-started-marker-do-not-remove

============
Contributing
============

See the `contributing document <CONTRIBUTING.rst>`_.

======
Citing
======

.. start-citing-do-not-remove

If you use zksk in your research, please cite like this:

.. code-block:: bibtex

    @inproceedings{LueksKFBT19,
      author    = {Wouter Lueks and
                   Bogdan Kulynych and
                   Jules Fasquelle and
                   Simon Le Bail{-}Collet and
                   Carmela Troncoso},
      title     = {zksk: {A} Library for Composable Zero-Knowledge Proofs},
      booktitle = {Proceedings of the 18th {ACM} Workshop on Privacy in the Electronic
                   Society ({WPES@CCS})},
      pages     = {50--54},
      year      = {2019},
    }

.. end-citing-do-not-remove

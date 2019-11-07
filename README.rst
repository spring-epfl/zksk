####
zksk
####

|build_status| |docs_status|

.. |build_status| image:: https://travis-ci.org/spring-epfl/zksk.svg?branch=master
   :target: https://travis-ci.org/spring-epfl/zksk
   :alt: Build status

.. |docs_status| image:: https://readthedocs.org/projects/zksk/badge/?version=latest
   :target: https://zksk.readthedocs.io/?badge=latest
   :alt: Documentation status

.. |arxiv| image:: https://img.shields.io/badge/cs.CR-arXiv%3A1911.02459-red
   :target: https://arxiv.org/abs/1911.02459
   :alt: Paper on arXiv

.. start-description-marker-do-not-remove

Zero-Knowledge Swiss Knife: Python library for prototyping composable zero-knowledge proofs.

.. end-description-marker-do-not-remove

Check out the `documentation <https://zksk.readthedocs.io/>`_.

> **Warning.** Please don't use this software for anything mission-critical. It is designed for quick protyping of privacy-enhancing technologies, not production use.


===============
Getting started
===============

.. start-getting-started-marker-do-not-remove

You can install zksk using pip:

.. code-block:: bash

   pip install -e .

To run unit tests, first, install the dev version of the package:

.. code-block:: bash

   pip install -e ".[dev]"

Second, run the tests with pytest:

.. code-block:: bash

   pytest

To build the the documentation pages, make sure you have installed the dev version of the package
(see above), and then run:

.. code-block:: bash

    cd docs/
    make html

.. end-getting-started-marker-do-not-remove

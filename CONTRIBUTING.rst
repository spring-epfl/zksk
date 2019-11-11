############
Contributing
############

.. start-content-do-not-remove

Thanks for looking into making zksk better! It's currently under active development, and we are
grateful for any help, bug reports, fixes, and new primitives.


Dev setup
=========

Package
^^^^^^^

Checkout the repository, and run in the directory:

.. code-block:: bash

    pip install -e ".[dev]"

This will install the dev version of the locally checked-out package

Testing
^^^^^^^

Use pytest to run the tests and get the coverage report:

.. code-block:: bash

    pytest

Docs
^^^^

To build the documentation pages run:

.. code-block:: bash

    cd docs/
    make html

They will be built in ``docs/_build/html``. You can run any static server to check them. For
example:

.. code-block:: bash

    cd docs/_build/html
    python -m http.server

Hooks
^^^^^

We use pre-commitment hooks for automatic code formatting. Set them up as follows:

.. code-block:: bash

    pre-commit install

Issues
======
Please create an issue on Github if you spot a bug or other problem.

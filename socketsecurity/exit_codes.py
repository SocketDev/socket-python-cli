"""Process exit codes, and the exceptions that map onto them.

``socketcli.cli()`` applies runtime failure policy using the configuration loaded
at startup. Argument validation exits with ``EXIT_USAGE`` directly; successful
reports and findings use OutputHandler, and SCM event filters may skip a run.

* ``EXIT_OK`` (0): successful report, skipped event, or ``--disable-blocking``.
* ``EXIT_BLOCKING`` (1): blocking security findings.
* ``EXIT_USAGE`` (2): invalid flags or configuration. The same code argparse uses
  for its own usage errors. ``--disable-blocking`` does not apply, because a
  misconfigured run never got far enough to scan anything.
* ``EXIT_INFRASTRUCTURE`` (3): missing credentials, API or environment failures.
  ``--exit-code-on-api-error`` replaces it; ``--disable-blocking`` turns it into 0.
* ``EXIT_INTERRUPTED`` (130): Ctrl+C / SIGINT, the POSIX 128 + signal number
  convention. ``--disable-blocking`` turns it into 0.

This module imports nothing from the package so config parsing can use it
without pulling in ``socketsecurity.core``.
"""

EXIT_OK = 0
EXIT_BLOCKING = 1
EXIT_USAGE = 2
EXIT_INFRASTRUCTURE = 3
EXIT_INTERRUPTED = 130


class InfrastructureError(Exception):
    """A run that cannot continue for a reason other than its own findings.

    Raise it instead of calling ``sys.exit`` so ``cli()`` can apply
    ``--disable-blocking`` and ``--exit-code-on-api-error``. The message is
    logged as is, without a traceback.
    """


class IncompleteComparisonError(InfrastructureError):
    """The API marked a scan comparison incomplete.

    An incomplete comparison can leave out alerts, so a passing result would not
    mean the change is clean.
    """

from pydantic_settings import BaseSettings, CliApp, CliSubCommand

from pulp_sec.bad import Bad
from pulp_sec.pypi import PyPi


class PulpSec(BaseSettings, cli_parse_args=True):
    bad: CliSubCommand[Bad]
    pypi: CliSubCommand[PyPi]

    def cli_cmd(self) -> None:
        CliApp.run_subcommand(self)


def main() -> None:
    CliApp.run(PulpSec)

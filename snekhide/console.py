import sys
from typing import BinaryIO, Optional, Any, Union
import typer


class DebuggableTyper(typer.Typer):
    _QUIET: bool = False
    _STDOUT_BIN: BinaryIO = None

    @staticmethod
    def enable_debug(flag: bool) -> bool:
        sys.tracebacklimit = None if flag else 0
        return flag

    @staticmethod
    def enable_silent(flag: bool) -> bool:
        DebuggableTyper._QUIET = True if flag else False
        return flag

    @staticmethod
    def _get_binary_stdout() -> BinaryIO:
        if DebuggableTyper._STDOUT_BIN is None:
            DebuggableTyper._STDOUT_BIN = typer.get_binary_stream('stdout')
        return DebuggableTyper._STDOUT_BIN

    def __call__(self, *args, **kwargs):
        sys.tracebacklimit = 0
        try:
            super(DebuggableTyper, self).__call__(*args, **kwargs)
        except (SystemExit, KeyboardInterrupt) as e:
            raise e
        except BaseException as e:
            if sys.tracebacklimit == 0:
                error("An unknown error occurred. Check logs using the --debug option for more information")
                sys.exit(1)
            else:
                raise e


def out(message: Optional[Any] = None) -> None:
    if not DebuggableTyper._QUIET:
        typer.secho(message=message)


def success(message: Optional[Any] = None, color: Optional[bool] = None) -> None:
    if not DebuggableTyper._QUIET:
        typer.secho(message=message, color=color, fg=typer.colors.BLUE)


def warn(message: Optional[Any] = None, color: Optional[bool] = None) -> None:
    if not DebuggableTyper._QUIET:
        typer.secho(message=message, color=color, fg=typer.colors.YELLOW)


def error(message: Optional[Any] = None, color: Optional[bool] = None) -> None:
    typer.secho(message=message, err=True, color=color, fg=typer.colors.RED)


def abort(message: Optional[Any] = None, color: Optional[bool] = None) -> None:
    typer.secho(message=message, err=True, color=color, fg=typer.colors.RED)
    raise typer.Exit(1)


def stream(bytes: Union[bytes, bytearray]) -> None:
    DebuggableTyper._get_binary_stdout().write(bytes)

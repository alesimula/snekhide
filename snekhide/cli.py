"""This module defines the CLI commands."""
# snekhide/cli.py

from typing import Optional
import typer
from pathlib import Path
import zstandard

from snekhide import __app_name__, __version__, encoder, console


app = console.DebuggableTyper(
    add_completion=False,
    help="Simple steganography command line tool to read and write encrypted data to an image",
    no_args_is_help=True
)

DEFAULT_TARGET = Path('{\asourcepath\a}\a.\asnek\a.\a{\asuffix\a}')


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"{__app_name__} v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    _debug: bool = typer.Option(
        False, "--debug",
        shell_complete=None,
        help="Enable printing stack trace",
        hidden=True,
        callback=app.enable_debug,
        is_eager=True,
        show_default=False
    ),
    _version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        shell_complete=None,
        help="Show the application's version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
    _cmd_help: Optional[bool] = typer.Option(
        None,
        "-\b\a[COMMAND]\u00A0--help",
        shell_complete=None,
        help="\a\u00A0\u00A0\u00A0Show help page for a command and exit.",
        is_eager=True,
    )
) -> None: return


@app.command(help="Hides data into an image")
def write(
    targetfile: Path = typer.Option(
        DEFAULT_TARGET,
        "--output",
        "-o",
        shell_complete=None,
        help="File to write to, cannot be the same as source",
        dir_okay=False,
        is_eager=True,
        show_default=True
    ),
    message: str = typer.Option(
        None,
        "--message",
        "-m",
        shell_complete=None,
        help="Write a text message instead of a binary file",
        show_default=False
    ),
    force_message: bool = typer.Option(
        False,
        "--force-message",
        "-M",
        shell_complete=None,
        help="Write data file in the form of a message; no extension will be saved and reading will print to stdout",
        show_default=False
    ),
    strength: int = typer.Option(
        6,
        "--strength",
        "-s",
        shell_complete=None,
        help="Password hashing strenght  [iterations: 10^{strength}]",
        is_eager=True,
        min=0,
        max=9,
        show_default=True
    ),
    compression_level: int = typer.Option(
        14,
        "--level",
        "-l",
        shell_complete=None,
        help="File compression level (zstd algorithm)",
        is_eager=True,
        min=0,
        max=zstandard.MAX_COMPRESSION_LEVEL,
        show_default=True
    ),
    password: str = typer.Option(
        None,
        "--password",
        "-p",
        shell_complete=None,
        help="Will use the provided password instead of prompting the user to enter a password at runtime",
        show_default=False
    ),
    write_stdout: bool = typer.Option(
        False,
        "--stdout",
        "-O",
        shell_complete=None,
        help="Enables quiet mode and writes resulting file to stdout; must always be used with the -p option",
        callback=app.enable_silent,
        show_default=False
    ),
    encryption: bool = typer.Option(
        True,
        "--disable-encryption",
        "-s\u00A00",
        shell_complete=None,
        help="Disable password encryption; data can be retrieved without a password",
        is_eager=True,
        show_default=False
    ),
    compression: bool = typer.Option(
        True,
        "--disable-compression",
        "-l\u00A00",
        shell_complete=None,
        help="Disable file compression; uncompressed data may take up more space or not fit",
        is_eager=True,
        show_default=False
    ),
    noise: bool = typer.Option(
        True,
        "--disable-noise",
        shell_complete=None,
        help="Disable encryption; only part of the image will be modified",
        is_eager=True,
        show_default=False
    ),
    extension: bool = typer.Option(
        True,
        "--disable-file-info",
        shell_complete=None,
        help="Disable saving original data file's information; currently only affects file extension",
        is_eager=True,
        show_default=False
    ),
    sourcefile: Path = typer.Argument(
        None,
        help="Source image to write data into; a copy will be created",
        exists=True,
        dir_okay=False
    ),
    datafile: Optional[Path] = typer.Argument(
        None,
        help="Data file to hide into the image; must not be passed if using the '-m' argument",
        exists=True,
        dir_okay=False
    )
) -> None:
    # Somehow the 'is' keyword does not work here
    target = None if DEFAULT_TARGET == targetfile else targetfile
    if message is not None and datafile is not None:
        console.abort("Cannot pass both a message and a data file")
    if message is None and datafile is None:
        console.abort("Either a message or data file must be passed")
    compression_level = compression_level if compression else 0
    strength = strength if encryption else 0
    if password is not None and strength == 0:
        console.abort("When encryption is disabled, it is not possible to set a password")
    if write_stdout and password is None and strength != 0:
        console.abort("""Writing to stdout requires the password to be passed with the -p option
                or encryption to be disabled""")
    data: bytes = message.encode('utf-8') if (datafile is None) else datafile.read_bytes()
    is_plaintext = force_message or datafile is None
    binary_plaintext = force_message and datafile is not None
    extension = extension and not is_plaintext
    extensions = datafile.suffixes if extension else []
    encoder.embed(sourcefile, data, noise, target=target, extensions=extensions, is_plaintext=is_plaintext,
                  binary_plaintext=binary_plaintext, hash_strength=strength, compression_level=compression_level,
                  write_stdout=write_stdout, password=password)
    raise typer.Exit(0)


@app.command(help="Reads hidden data of an image")
def read(
    password: str = typer.Option(
        None,
        "--password",
        "-p",
        shell_complete=None,
        help="Will use the provided password instead of prompting the user to enter a password at runtime",
        show_default=False
    ),
    write_stdout: bool = typer.Option(
        False,
        "--stdout",
        "-O",
        shell_complete=None,
        help="Enables quiet mode and writes decoded message to stdout; must always be used with the -p option",
        callback=app.enable_silent,
        show_default=False
    ),
    sourcefile: Path = typer.Argument(
        None,
        help="Image to read data from; a data file will be created by default unless it contains a text message",
        exists=True,
        dir_okay=False
    ),
) -> None:
    # The write_stdout without password check is executed inside the read method to allow it on unencrypted files
    encoder.read(sourcefile, write_stdout=write_stdout, password=password)
    raise typer.Exit(0)

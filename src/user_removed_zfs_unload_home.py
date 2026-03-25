#!/usr/bin/env python3
import asyncio
import fcntl
import logging
import os.path as ospath
import pwd
import signal
import subprocess
import sys

from argparse import ArgumentParser
from asyncio import CancelledError
from contextlib import contextmanager, ExitStack
from dataclasses import dataclass
from dbus_next.aio import MessageBus
from dbus_next.constants import BusType
from functools import partial
from logging import StreamHandler
from logging.handlers import SysLogHandler
from subprocess import CalledProcessError
from typing import Any, Optional, Sequence


logger = logging.getLogger()
"""The logger."""


LOGGER_ADDRESS = "/dev/log"
"""The default logger address."""


IDENT = ospath.basename(__file__)
"""The ident used for syslog entries."""


DEFAULT_RUNSTATEDIR = "/run"
"""The default run state directory."""


@dataclass(frozen=True, slots=True)
class Session:
    """Encapsulates a session."""

    zfs_pam_key_dir: str
    """The directory in which the user session counter files are 
    stored."""

    def __init__(self, runstate_dir: Optional[str]) -> None:
        """Initialize the `Session`.

        Args:
            runstate_dir (str, optional): The run state directory.
                Defaults to `DEFAULT_RUNSTATEDIR`.
        """
        if runstate_dir is None:
            runstate_dir = DEFAULT_RUNSTATEDIR
        object.__setattr__(
            self, "zfs_pam_key_dir", ospath.join(runstate_dir, "pam_zfs_key")
        )


def check_call(cmd: Sequence[str]) -> int:
    """Similar to `subprocess.check_call`, but also captures the output
    as text.

    Args:
        cmd (Sequence[str]): The command.

    Returns:
        int: The returncode of the subprocess (should always be 0).
    """
    cproc = subprocess.run(cmd, capture_output=True, check=True, text=True)
    return cproc.returncode


def fmt_zfs_stderr(data: Any) -> str:
    """Formats the stderr output of zfs for printing to the syslog.

    Args:
        data (Any): The data (for example `CalledProcessError.stderr`).

    Returns:
        str: The formatted string to be written to the syslog as part of
            the log message.
    """
    if data is None:
        return "None"
    if isinstance(data, str):
        return data.strip()
    if isinstance(data, bytes):
        return data.decode().strip()
    logger.warning("Unknown zfs stderr: %r", data)
    return repr(data)


@dataclass(frozen=True, slots=True)
class DatasetInfo:
    """The result of a search for the dataset name given the 
    mountpoint."""

    mounted: bool
    """Whether the dataset is mounted."""

    name: str
    """The name of the dataset."""


class DatasetNotFound:
    """The result of a search for the dataset name given the 
    mountpoint if the zfs command failed or the dataset was not found.
    """
    pass


def get_zfs_dataset_name(mountpoint: str) -> DatasetInfo | DatasetNotFound:
    """Get the name of a zfs dataset given its mountpoint.

    Args:
        mountpoint (str): The mountpoint.

    Returns:
        DatasetNameState: Information regarding the result of the
            search.
    """

    zfs_list_cmd = ["zfs", "list", "-H", "-o", "name,mountpoint,mounted"]

    try:
        output = subprocess.check_output(zfs_list_cmd, text=True)
    except CalledProcessError as cpe:
        logger.critical(
            "Error obtaining dataset info from zfs: %r",
            fmt_zfs_stderr(cpe.stderr)
        )
        return DatasetNotFound()
    
    mountpoint = ospath.normpath(ospath.realpath(mountpoint))

    for line in output.strip().splitlines():
        name, dsmpt, mounted = line.split()
        if ospath.normpath(dsmpt.strip()) != mountpoint:
            continue
        if mounted.lower() != 'yes':
            return DatasetInfo(False, name)
        return DatasetInfo(True, name)

    logger.info("User home dir not mounted: zfs not listing mountpoint.")
    return DatasetNotFound()


def lock_user_home(uid: int) -> None:
    """Unmount the home of the user with the provided UID if it is a zfs
    dataset and unload the key of the dataset. If this is not possible,
    a message with the error description will be written to the logger.

    Args:
        uid (int): The user ID.
    """

    try:
        struct_passwd = pwd.getpwuid(uid)
    except KeyError:
        logger.warning("Cannot access passwd struct for user %r.", uid)
        return

    home_dir = struct_passwd.pw_dir

    if len(home_dir.strip()) == 0:
        logger.info("No home directory specified for user %r.", uid)
        return

    sresult = get_zfs_dataset_name(home_dir)
    if isinstance(sresult, DatasetNotFound):
        return

    dataset_name = sresult.name

    logger.debug("Dataset for user %r: %r", uid, dataset_name)

    try:
        keystatus = subprocess.check_output(
            ["zfs", "get", "-H", "-o", "value", "keystatus", dataset_name],
            text=True
        )
    except CalledProcessError as cpe:
        logger.critical(
            "Unable to determine keystatus for user %r: %r",
            uid,
            fmt_zfs_stderr(cpe.stderr)
        )
        return
    
    keystate = keystatus.strip().lower()

    if (len(keystate) == 0) or (keystate == '-'):
        logger.info("Home of user %r not encrypted. Skipping.", uid)
        return

    if keystate == "unavailable":
        logger.info("Key already unloaded for user %r.", uid)
        return

    if keystate != "available":
        logger.warning(
            "Unexpected key status for user %r: %r. Ignoring.",
            uid,
            keystate
        )
        return

    if sresult.mounted:
        try:
            check_call(["zfs", "unmount", dataset_name])
        except CalledProcessError as cpe:
            logger.critical(
                "Error unmounting home dataset for user %r: %r",
                uid,
                fmt_zfs_stderr(cpe.stderr)
            )
            return
        logger.info("Unmounted home directory for user %r.", uid)
    else:
        logger.info("Home directory for user %r not mounted from zfs.", uid)
        # Even if the directory is not mounted, the key may still be
        # loaded nonetheless. Thus, we cannot return here.

    try:
        check_call(["zfs", "unload-key", dataset_name])
    except CalledProcessError as cpe:
        logger.critical(
            "Unable to unload key for user %r: %r",
            uid,
            fmt_zfs_stderr(cpe.stderr)
        )
        return

    logger.info("Unloaded key for home directory for user %r.", uid)


@contextmanager
def open_locked_session_counter_file(path: str):
    """Open the specifie file and flock it for exclusive acces. Read the
    file's content and return it.

    Args:
        path (str): The path of the file.

    Yields:
        str or Exception: The file content or the exception that
            occurred when opening the file.
    """
    with ExitStack() as es:
        try:
            ifi = es.enter_context(open(path, 'r'))
        except Exception as err:
            yield err
            return
        
        fcntl.flock(ifi, fcntl.LOCK_EX)
        yield ifi.read()


def try_lock_user_home(session: Session, uid: int):
    """Attempt to lock the user home if it is a zfs dataset. If
    applicable and possible, unmount the users home directory and then
    unload the dataset key.

    Args:
        session (Session): The session
        uid (int): The UID of the user whose home directory to lock.
    """
    counter_path = ospath.join(session.zfs_pam_key_dir, str(uid))

    with open_locked_session_counter_file(counter_path) as sc_result:

        if isinstance(sc_result, FileNotFoundError):
            logger.debug("No session counter file for %r found.", uid)
            return
        if isinstance(sc_result, Exception):
            logger.critical(
                "Could not open session counter file for user %r.", uid
            )
            return

        try:
            num_sessions = int(sc_result)
        except ValueError:
            logger.critical(
                "Unable to parse session counter %r for user %r.",
                sc_result,
                uid
            )
            return

        if num_sessions != 0:
            # This can for example happen if the user logs back in
            # directly after the handler is called. If all sessions
            # were previously terminated and the handler was called,
            # logging back in directly before the lock on the
            # session counter file is acquired results in "1" being
            # inside the counter file. In this case we cannot safely
            # unmount. Otherwise the user would end up without a
            # mounted home directory.
            logger.debug("User has active sessions!")
            return

        # The counter file must remain locked while unmounting the
        # home directory to prevent race conditions. If this locking
        # is not done, pam_zfs_key could attempt to mount the home
        # directory if the user logs back in immediately, followed
        # by an unmount of this script, which would leave the user
        # without a mounted home directory. 
        logger.debug("Trying to unmount home of user %r...", uid)
        lock_user_home(uid)


def on_user_removed(session: Session, uid: int, user_path: str):
    """Handler for the D-BUS UserRemoved event.

    Args:
        session (Session): The session of this handler script.
        uid (int): The UID of the user whose session was removed.
        user_path (str): This parameter is only logged at level DEBUG.
    """
    logger.debug("User removed: %r, path: %r.", uid, user_path)

    if uid < 1000:
        logger.debug("Is a system user: %r.", uid)
        return

    try_lock_user_home(session, uid)


@dataclass(frozen=True, slots=True)
class Args:
    """Encapsulates the command line arguments."""

    verbose: bool
    """Whether to print debug output."""

    log_tee_stderr: bool
    """Whether to tee the syslog to stderr."""

    runstatedir: Optional[str]
    """The provided runstate dir."""

    log_device: Optional[str]
    """The provided log device."""

    @classmethod
    def parse_args(cls) -> "Args":
        """Parse the command line arguments.

        Returns:
            Args: An instance of the `Args` class containing the parsed
                arguments.
        """
        parser = ArgumentParser()
        parser.add_argument(
            "--verbose", "-v", action="store_true", default=False, 
        )
        parser.add_argument(
            "--log-tee-stderr", action="store_true", default=False, 
            help="Also write log messages to stderr."
        )
        parser.add_argument(
            "--runstatedir", default=None, 
            help="The runstate dir, defaults to /run."
        )
        parser.add_argument(
            "--log-device", default=None, 
            help=(
                "The log device to write messages to. Defaults to /dev/log."
            )
        )
        args = parser.parse_args()
        return cls(
            verbose=args.verbose,
            log_tee_stderr=args.log_tee_stderr,
            runstatedir=args.runstatedir,
            log_device=args.log_device
        )


def setup_logging(
    verbose: bool, log_tee_stderr: bool, log_device: Optional[str]
) -> None:
    """Set up the logging.

    Args:
        verbose (bool): Whether to print debug output.
        log_tee_stderr (bool): Whether to set up a logger which tees
            logs to stderr.
        log_device (str, optional): The log device. Defaults to
            `LOGGER_ADDRESS`.
    """
    if verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    if log_device is None:
        log_device = LOGGER_ADDRESS
    handler = SysLogHandler(log_device, SysLogHandler.LOG_DAEMON)
    handler.ident = f"{IDENT}: "
    logger.addHandler(handler)
    if log_tee_stderr:
        stderr_handler = StreamHandler(sys.stdout)
        logger.addHandler(stderr_handler)


async def main(args: Args) -> int:
    """The main function.

    Args:
        args (Args): The command line arguments.

    Returns:
        int: The exit code.
    """

    setup_logging(args.verbose, args.log_tee_stderr, args.log_device)

    logger.info("Startup.")
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()

    introspection = await bus.introspect(
        "org.freedesktop.login1", "/org/freedesktop/login1"
    )

    obj = bus.get_proxy_object(
        "org.freedesktop.login1", "/org/freedesktop/login1", introspection
    )

    session = Session(args.runstatedir)

    manager = obj.get_interface("org.freedesktop.login1.Manager")
    handler = partial(on_user_removed, session)
    manager.on_user_removed(handler)  # type: ignore [attr-defined]

    loop = asyncio.get_event_loop()

    def exception_handler(loop, context):
        logger.critical("Unhandled exception: %r", context.message)

    loop.set_exception_handler(exception_handler)

    eternal_future = loop.create_future()

    def handle_shutdown():
        logger.debug("Received SIGINT or SIGTERM.")
        eternal_future.cancel()

    loop.add_signal_handler(signal.SIGINT, handle_shutdown)
    loop.add_signal_handler(signal.SIGTERM, handle_shutdown)

    logger.info("Awaiting signals.")
    try:
        await eternal_future
    except CancelledError:
        logger.debug("Cancelled eternal future.")

    return 0


async def _main() -> int:
    """The main function called by the script. Parses arguments and
    calls `main`.

    Returns:
        int: The exit code.
    """
    args = Args.parse_args()
    return await main(args)


if __name__ == "__main__":
    exitcode = asyncio.run(_main())
    exit(exitcode)

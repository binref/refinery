from __future__ import annotations

import sys

from subprocess import PIPE, Popen

from refinery.lib.meta import metavars
from refinery.lib.structures import MemoryFile
from refinery.lib.types import Param
from refinery.units import Arg, RefineryPartialResult, Unit


class run(Unit):
    """
    Turns any command into a refinery unit. Data is processed by feeding it to the standard input
    of a process spawned from the given command line, and then reading the standard output of that
    process as the result of the operation. The main purpose of this unit is to allow using the
    syntax from `refinery.lib.frame` with other command line tools. By default, the unit streams
    the output from the executed command as individual outputs, but the `buffer` option can be set
    to buffer all output of a single execution. The format string expression `{}` or `{0}` can be
    used as one of the arguments passed to the external command to represent the incoming data. In
    this case, the data will not be sent to the standard input device of the new process.
    """

    _JOIN_TIME = 0.1

    def __init__(
        self, *commandline: Param[str, Arg.String(nargs='...', metavar='(all remaining)', help=(
            'All remaining command line tokens form an arbitrary command line to be executed. Use'
            ' format string syntax to insert meta variables and incoming data chunks.'))],
        stream: Param[bool, Arg.Switch('-s',
            help='Stream the command output rather than buffering it.')] = False,
        noinput: Param[bool, Arg.Switch('-x', help='Do not send any input to the new process.')] = False,
        errors: Param[bool, Arg.Switch('-m', help=(
            'Merge stdout and stderr. By default, the standard error stream of the coupled command'
            ' is forwarded to the logger, i.e. it is only visible if -v is also specified.'
        ))] = False,
        timeout: Param[float, Arg.Double('-t', metavar='T', help=(
            'Optionally set an execution timeout as a floating point number in seconds.'
        ))] = 0.0
    ):
        if not commandline:
            raise ValueError('you need to provide a command line.')
        super().__init__(
            commandline=commandline, errors=errors, noinput=noinput, stream=stream, timeout=timeout)

    def process(self, data):
        def shlexjoin():
            import shlex
            return shlex.join(commandline)

        meta = metavars(data)
        meta.ghost = True
        used = set()
        commandline = [
            meta.format(cmd, self.codec, [data], None, False, used=used)
            for cmd in self.args.commandline
        ]

        if self.args.noinput:
            self.log_info('sending no input to process stdin')
            data = None

        if not self.log_debug(commandline):
            self.log_info(shlexjoin)

        posix = 'posix' in sys.builtin_module_names
        process = Popen(commandline, shell=True,
            stdin=PIPE, stdout=PIPE, stderr=PIPE, close_fds=posix)

        if not self.args.stream and not self.args.timeout:
            out, err = process.communicate(data)
            for line in err.splitlines():
                self.log_info(line)
            yield out
            return

        from queue import Empty, Queue
        from threading import Event, Thread
        from time import process_time, sleep

        start = 0
        result = None

        qerr = Queue()
        qout = Queue()
        done = Event()

        def adapter(stream, queue: Queue, event: Event):
            while not event.is_set():
                out = stream.read1()
                if out:
                    queue.put(out)
                else:
                    break
            stream.close()

        recvout = Thread(target=adapter, args=(process.stdout, qout, done), daemon=True)
        recverr = Thread(target=adapter, args=(process.stderr, qerr, done), daemon=True)

        recvout.start()
        recverr.start()

        if data:
            process.stdin.write(data)
        process.stdin.close()
        start = process_time()

        if not self.args.stream or self.args.timeout:
            result = MemoryFile()

        def queue_read(q: Queue):
            try:
                return q.get_nowait()
            except Empty:
                return None

        errbuf = MemoryFile()

        while True:
            out = queue_read(qout)
            err = None

            if self.args.errors:
                out = out or queue_read(qerr)
            else:
                err = queue_read(qerr)

            if err and self.log_info():
                errbuf.write(err)
                errbuf.seek(0)
                lines = errbuf.readlines()
                errbuf.seek(0)
                errbuf.truncate()
                if lines:
                    if not (done.is_set() or lines[~0].endswith(B'\n')):
                        errbuf.write(lines.pop())
                    for line in lines:
                        if line := line.rstrip(B'\n'):
                            self.log_info(line)
            if out:
                if not self.args.stream or self.args.timeout:
                    result.write(out)
                if self.args.stream:
                    yield out

            if done.is_set():
                if recverr.is_alive():
                    self.log_warn('stderr receiver thread zombied')
                if recvout.is_alive():
                    self.log_warn('stdout receiver thread zombied')
                break
            elif not err and not out and process.poll() is not None:
                recverr.join(self._JOIN_TIME)
                recvout.join(self._JOIN_TIME)
                done.set()
            elif self.args.timeout:
                if process_time() - start > self.args.timeout:
                    self.log_info('terminating process after timeout expired')
                    done.set()
                    process.terminate()
                    for wait in range(4):
                        if process.poll() is not None:
                            break
                        sleep(self._JOIN_TIME)
                    else:
                        self.log_warn('process termination may have failed')
                    recverr.join(self._JOIN_TIME)
                    recvout.join(self._JOIN_TIME)
                    if not len(result):
                        result = RuntimeError('timeout reached, process had no output')
                    else:
                        result = RefineryPartialResult(
                            'timeout reached, returning all collected output',
                            partial=result.getvalue())

        if isinstance(result, Exception):
            raise result
        elif not self.args.stream:
            yield result.getvalue()

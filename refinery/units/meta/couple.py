#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import io
import sys

from threading import Thread, Event
from subprocess import PIPE, Popen
from queue import Queue, Empty
from time import process_time, sleep

from .. import arg, Unit, RefineryPartialResult


class couple(Unit):
    """
    Turns any command into a refinery unit. Data is processed by feeding it to the
    standard input of a process spawned from the given command line, and then reading
    the standard output of that process as the result of the operation. The main
    purpose of this unit is to allow using the syntax from `refinery.lib.frame` with
    other command line tools. By default, `refinery.couple` streams the output from
    the executed command as individual outputs, but the `buffer` option can be set to
    buffer all output of a single execution.
    """

    def __init__(
        self, *commandline : arg(
            nargs='+',
            type=str,
            help='Part of an arbitrary command line to be executed.',
            metavar='token'),
        buffer  : arg.switch('-b', help='Buffer the command output for one execution rather than streaming it.') = False,
        timeout : arg('-t', metavar='T', help='Set an execution timeout as a floating point number in seconds, there is none by default.') = 0.0
    ) -> Unit: pass

    def process(self, data):
        self.log_debug(lambda: __import__('shlex').join(self.args.commandline))

        posix = 'posix' in sys.builtin_module_names
        process = Popen(self.args.commandline,
            stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=False, close_fds=posix)

        result = None

        qerr = Queue()
        qout = Queue()
        done = Event()

        def adapter(stream, queue: Queue, event: Event):
            while not event.is_set():
                out = stream.read1()
                if out: queue.put(out)
                else: break
            stream.close()

        recvout = Thread(target=adapter, args=(process.stdout, qout, done), daemon=True)
        recverr = Thread(target=adapter, args=(process.stderr, qerr, done), daemon=True)

        recvout.start()
        recverr.start()

        process.stdin.write(data)
        process.stdin.close()

        if self.args.buffer or self.args.timeout:
            result = io.BytesIO()

        if self.args.timeout:
            start = process_time()

        while True:

            try:
                err = qerr.get_nowait()
            except Empty:
                err = None
            else:
                self.log_debug(err)

            try:
                out = qout.get_nowait()
            except Empty:
                out = None
            else:
                if self.args.buffer or self.args.timeout:
                    result.write(out)
                elif not self.args.buffer:
                    yield out

            if not err and not out and process.poll() is not None:
                break
            elif self.args.timeout:
                if process_time() - start > self.args.timeout:
                    self.log_info('terminating process after timeout expired')
                    done.set()
                    process.terminate()
                    for wait in range(4):
                        if process.poll() is not None: break
                        sleep(.1)
                    else:
                        self.log_warn('process termination may have failed')
                    result = result.getvalue()
                    if not result:
                        result = RuntimeError('timeout reached, process had no output')
                    else:
                        result = RefineryPartialResult(
                            'timeout reached, returning all collected output',
                            partial=result)
                    break

        recverr.join(0.4)
        recvout.join(0.4)

        if recverr.is_alive():
            self.log_warn('stderr receiver thread zombied')
        if recvout.is_alive():
            self.log_warn('stdout receiver thread zombied')

        if isinstance(result, Exception):
            raise result
        elif self.args.buffer:
            yield result.getvalue()

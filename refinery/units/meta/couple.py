#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os

from subprocess import PIPE, Popen

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
        self, *commandline : arg(nargs='...', metavar='(all remaining)',
            help='An arbitrary command line to be executed.'),
        buffer: arg.switch('-b', help='Buffer the command output for one execution rather than streaming it.') = False,
        timeout: arg('-t', metavar='T',
            help='Set an execution timeout as a floating point number in seconds, there is none by default.') = 0.0
    ):
        if not commandline:
            raise ValueError('you need to provide a command line.')
        super().__init__(commandline=commandline, buffer=buffer, timeout=timeout)

    def process(self, data):
        def shlexjoin():
            import shlex
            return ' '.join(shlex.quote(cmd) for cmd in commandline)

        commandline = [cmd.decode(self.codec) for cmd in self.args.commandline]
        self.log_debug(shlexjoin)

        posix = 'posix' in sys.builtin_module_names
        shell = os.name == 'nt'
        process = Popen(commandline,
            stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=shell, close_fds=posix)

        if self.args.buffer and not self.args.timeout:
            out, err = process.communicate(data)
            for line in err.splitlines():
                self.log_debug(line)
            yield out
            return

        import io
        from threading import Thread, Event
        from queue import Queue, Empty
        from time import process_time, sleep

        start = 0
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
        start = process_time()

        if self.args.buffer or self.args.timeout:
            result = io.BytesIO()

        def queue_read(q: Queue):
            try: return q.get_nowait()
            except Empty: return None

        errbuf = io.BytesIO()

        while True:

            err = queue_read(qerr)
            out = queue_read(qout)
            if err and self.log_debug():
                errbuf.write(err)
                errbuf.seek(0)
                lines = errbuf.readlines()
                errbuf.seek(0)
                errbuf.truncate()
                if lines:
                    if not (done.is_set() or lines[~0].endswith(B'\n')):
                        errbuf.write(lines.pop())
                    for line in lines:
                        msg = line.rstrip(B'\n')
                        if msg: self.log_debug(msg)
            if out:
                if self.args.buffer or self.args.timeout:
                    result.write(out)
                if not self.args.buffer:
                    yield out

            if done.is_set():
                if recverr.is_alive():
                    self.log_warn('stderr receiver thread zombied')
                if recvout.is_alive():
                    self.log_warn('stdout receiver thread zombied')
                break
            elif not err and not out and process.poll() is not None:
                recverr.join(0.4)
                recvout.join(0.4)
                done.set()
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
                    recverr.join(0.4)
                    recvout.join(0.4)
                    if not len(result.getbuffer()):
                        result = RuntimeError('timeout reached, process had no output')
                    else:
                        result = RefineryPartialResult(
                            'timeout reached, returning all collected output',
                            partial=result.getvalue())

        if isinstance(result, Exception):
            raise result
        elif self.args.buffer:
            yield result.getvalue()

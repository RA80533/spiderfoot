from __future__ import annotations

import logging
import queue
import threading
import typing
from contextlib import suppress
from time import sleep


_T = typing.TypeVar("_T")


_P = typing.ParamSpec("_P")


_CallbackTuple = tuple[typing.Callable[..., _T], tuple, dict[str, ...]]


# 4 in test/unit/spiderfoot/test_spiderfootthreadpool.py
# 3 in sfscan.py
# 3 in spiderfoot/plugin.py
# 2 in spiderfoot/threadpool.py
# 1 in spiderfoot/__init__.py
class SpiderFootThreadPool(typing.Generic[_T]):
    """
    Each thread in the pool is spawned only once, and reused for best performance.

    Example 1: using map()
        with SpiderFootThreadPool(self.opts["_maxthreads"]) as pool:
            # callback("a", "arg1"), callback("b", "arg1"), ...
            for result in pool.map(
                    callback,
                    ["a", "b", "c", "d"],
                    "arg1",
                    taskName="sfp_testmodule"
                    saveResult=True
                ):
                yield result

    Example 2: using submit()
        with SpiderFootThreadPool(self.opts["_maxthreads"]) as pool:
            pool.start()
            # callback("arg1"), callback("arg2")
            pool.submit(callback, "arg1", taskName="sfp_testmodule", saveResult=True)
            pool.submit(callback, "arg2", taskName="sfp_testmodule", saveResult=True)
            for result in pool.shutdown()["sfp_testmodule"]:
                yield result
    """
    _log: logging.Logger
    _threads: int
    _qsize: int
    _pool: list[ThreadPoolWorker[_T] | None]
    _name: str
    _inputThread: threading.Thread | None
    inputQueues: dict[str, queue.Queue[_CallbackTuple[_T]]]
    _outputQueues: dict[str, queue.Queue[_T]]
    _stop: bool
    _lock: threading.Lock

    # 3 in test/unit/spiderfoot/test_spiderfootthreadpool.py
    # 1 in sfscan.py
    # 1 in spiderfoot/plugin.py
    # 1 in spiderfoot/threadpool.py
    def __init__(self, threads: int = 100, qsize: int = 10, name: str = '') -> None:
        """Initialize the SpiderFootThreadPool class.

        Args:
            threads (int): Max number of threads
            qsize (int): Queue size
            name (str): Name
        """
        self._log = logging.getLogger(f"spiderfoot.{__name__}")
        self._threads = int(threads)
        self._qsize = int(qsize)
        self._pool = [None] * self._threads
        self._name = str(name)
        self._inputThread = None
        self.inputQueues = dict()
        self._outputQueues = dict()
        self._stop = False
        self._lock = threading.Lock()

    # 2 in spiderfoot/threadpool.py
    # 2 in test/unit/spiderfoot/test_spiderfootthreadpool.py
    # 1 in sfscan.py
    def start(self) -> None:
        self._log.debug(f'Starting thread pool "{self._name}" with {self._threads:,} threads')
        for i in range(self._threads):
            t = ThreadPoolWorker(pool=self, name=f"{self._name}_worker_{i + 1}")
            t.start()
            self._pool[i] = t

    # 7 in spiderfoot/threadpool.py
    @property
    def stop(self) -> bool:
        return self._stop

    @stop.setter
    def stop(self, val: bool) -> None:
        assert val in (True, False), "stop must be either True or False"
        for t in self._pool:
            with suppress(Exception):
                t.stop = val
        self._stop = val

    # 2 in spiderfoot/threadpool.py
    # 2 in test/unit/spiderfoot/test_spiderfootthreadpool.py
    # 1 in sfscan.py
    def shutdown(self, wait: bool = True) -> dict[str, list[_T]]:
        """Shut down the pool.

        Args:
            wait (bool): Whether to wait for the pool to finish executing

        Returns:
            results (dict): (unordered) results in the format: {"taskName": [returnvalue1, returnvalue2, ...]}
        """
        results = dict[str, list[_T]]()
        self._log.debug(f'Shutting down thread pool "{self._name}" with wait={wait}')
        if wait:
            while not self.finished and not self.stop:
                with self._lock:
                    outputQueues = list(self._outputQueues)
                for taskName in outputQueues:
                    moduleResults = list(self.results(taskName))
                    try:
                        results[taskName] += moduleResults
                    except KeyError:
                        results[taskName] = moduleResults
                sleep(.1)
        self.stop = True
        # make sure input queues are empty
        with self._lock:
            inputQueues = list(self.inputQueues.values())
        for q in inputQueues:
            with suppress(Exception):
                while 1:
                    q.get_nowait()
            with suppress(Exception):
                q.close()
        # make sure output queues are empty
        with self._lock:
            outputQueues = list(self._outputQueues.items())
        for taskName, q in outputQueues:
            moduleResults = list(self.results(taskName))
            try:
                results[taskName] += moduleResults
            except KeyError:
                results[taskName] = moduleResults
            with suppress(Exception):
                q.close()
        return results

    # 2 in spiderfoot/threadpool.py
    # 2 in test/unit/spiderfoot/test_spiderfootthreadpool.py
    def submit(
        self,
        callback: typing.Callable[_P, _T],
        *args: _P.args,
        **kwargs: _P.kwargs,
    ) -> None:
        """Submit a function call to the pool.
        The "taskName" and "maxThreads" arguments are optional.

        Args:
            callback (function): callback function
            *args: Passed through to callback
            **kwargs: Passed through to callback, except for taskName and maxThreads
        """
        taskName = kwargs.get('taskName', 'default')
        assert isinstance(taskName, str)
        maxThreads = kwargs.pop('maxThreads', 100)
        assert isinstance(maxThreads, int)
        # block if this module's thread limit has been reached
        while self.countQueuedTasks(taskName) >= maxThreads:
            sleep(.01)
            continue
        self._log.debug(f"Submitting function \"{callback.__name__}\" from module \"{taskName}\" to thread pool \"{self._name}\"")
        self.inputQueue(taskName).put((callback, args, kwargs))

    # 3 in spiderfoot/threadpool.py
    def countQueuedTasks(self, taskName: str) -> int:
        """For the specified task, returns the number of queued function calls
        plus the number of functions which are currently executing

        Args:
            taskName (str): Name of task

        Returns:
            int: the number of queued function calls plus the number of functions which are currently executing
        """
        queuedTasks = 0
        with suppress(Exception):
            queuedTasks += self.inputQueues[taskName].qsize()
        runningTasks = 0
        for t in self._pool:
            with suppress(Exception):
                if t.taskName == taskName:
                    runningTasks += 1
        return queuedTasks + runningTasks

    # 1 in spiderfoot/threadpool.yp
    def inputQueue(self, taskName: str = "default") -> queue.Queue[_CallbackTuple]:
        try:
            return self.inputQueues[taskName]
        except KeyError:
            self.inputQueues[taskName] = queue.Queue(self._qsize)
            return self.inputQueues[taskName]

    # 3 in spiderfoot/threadpool.py
    def outputQueue(self, taskName: str = "default") -> queue.Queue[_T]:
        try:
            return self._outputQueues[taskName]
        except KeyError:
            self._outputQueues[taskName] = queue.Queue(self._qsize)
            return self._outputQueues[taskName]

    # 2 in test/unit/spiderfoot/test_spiderfootthreadpool.py
    # 1 in spiderfoot/threadpool.py
    def map(
        self,
        callback: typing.Callable[_P, _T],
        iterable,
        *args: _P.args,
        **kwargs: _P.kwargs,
    ) -> typing.Generator[_T, None, None]:  # noqa: A003
        """map.

        Args:
            callback: the function to thread
            iterable: each entry will be passed as the first argument to the function
            args: additional arguments to pass to callback function
            kwargs: keyword arguments to pass to callback function

        Yields:
            return values from completed callback function
        """
        taskName = kwargs.get("taskName", "default")
        assert isinstance(taskName, str)
        self._inputThread = threading.Thread(target=self.feedQueue, args=(callback, iterable, args, kwargs))
        self._inputThread.start()
        self.start()
        sleep(.1)
        yield from self.results(taskName, wait=True)

    # # 4 in spiderfoot/threadpool.py
    def results(
        self,
        taskName: str = "default",
        wait: bool = False,
    ) -> typing.Generator[_T, None, None]:
        while 1:
            result = False
            with suppress(Exception):
                while 1:
                    yield self.outputQueue(taskName).get_nowait()
                    result = True
            if self.countQueuedTasks(taskName) == 0 or not wait:
                break
            if not result:
                # sleep briefly to save CPU
                sleep(.1)

    # 1 in spiderfoot/threadpool.py
    def feedQueue(
        self,
        callback: typing.Callable[_P, _T],
        iterable,
        *args: _P.args,
        **kwargs: _P.kwargs,
    ) -> None:
        for i in iterable:
            if self.stop:
                break
            self.submit(callback, i, *args, **kwargs)

    # 1 in spiderfoot/threadpool.py
    @property
    def finished(self) -> bool:
        if self.stop:
            return True

        finishedThreads = [not t.busy for t in self._pool if t is not None]
        try:
            inputThreadAlive = self._inputThread.is_alive()
        except AttributeError:
            inputThreadAlive = False

        inputQueuesEmpty = [q.empty() for q in self.inputQueues.values()]
        return not inputThreadAlive and all(inputQueuesEmpty) and all(finishedThreads)

    def __enter__(self) -> typing.Self:
        return self

    def __exit__(self) -> None:
        self.shutdown()


# 3 in spiderfoot/threadpool.py
class ThreadPoolWorker(threading.Thread, typing.Generic[_T]):
    _log: logging.Logger
    _pool: SpiderFootThreadPool[_T]
    taskName: str
    busy: bool
    stop: bool

    # 1 in spiderfoot/threadpool.py
    def __init__(
        self,
        pool: SpiderFootThreadPool[_T],
        name: str | None = None,
    ) -> None:

        self._log = logging.getLogger(f"spiderfoot.{__name__}")
        self._pool = pool
        self.taskName = ""  # which module submitted the callback
        self.busy = False
        self.stop = False

        super().__init__(name=name)

    # 1 in spiderfoot/threadpool.py
    def run(self) -> None:
        # Round-robin through each module's input queue
        while not self.stop:
            ran = False
            with self._pool._lock:
                inputQueues = list(self._pool.inputQueues.values())
            for q in inputQueues:
                if self.stop:
                    break
                try:
                    self.busy = True
                    callback, args, kwargs = q.get_nowait()
                    taskName = kwargs.pop("taskName", "default")
                    assert isinstance(taskName, str)
                    self.taskName = taskName
                    saveResult = kwargs.pop("saveResult", False)
                    assert isinstance(saveResult, bool)
                    try:
                        result = callback(*args, **kwargs)
                        ran = True
                    except Exception:  # noqa: B902
                        import traceback
                        self._log.error(f'Error in thread worker {self.name}: {traceback.format_exc()}')
                        break
                    if saveResult:
                        self._pool.outputQueue(self.taskName).put(result)
                except queue.Empty:
                    self.busy = False
                finally:
                    self.busy = False
                    self.taskName = ""
            # sleep briefly to save CPU
            if not ran:
                sleep(.05)

from __future__ import annotations

from collections import deque
from threading import Condition
from typing import Deque, Generic, Optional, TypeVar

T = TypeVar("T")


class ThreadSafeQueue(Generic[T]):
    def __init__(self) -> None:
        self._queue: Deque[T] = deque()
        self._cond = Condition()
        self._closed = False

    def push(self, item: T) -> None:
        with self._cond:
            if self._closed:
                return
            self._queue.append(item)
            self._cond.notify()

    def pop(self) -> Optional[T]:
        with self._cond:
            while not self._queue and not self._closed:
                self._cond.wait()
            if not self._queue:
                return None
            return self._queue.popleft()

    def close(self) -> None:
        with self._cond:
            self._closed = True
            self._cond.notify_all()

    def size(self) -> int:
        with self._cond:
            return len(self._queue)

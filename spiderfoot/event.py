from __future__ import annotations

import hashlib
import random
from time import time


# 34 in test/unit/spiderfoot/test_spiderfootevent.py
# 17 in test/unit/spiderfoot/test_spiderfootdb.py
# 11 in test/unit/spiderfoot/test_spiderfootplugin.py
#  6 in sfscan.py
#  5 in spiderfoot/event.py
#  4 in spiderfoot/db.py
#  3 in spiderfoot/plugin.py
#  1 in spiderfoot/__init__.py
# … 1,841 others
class SpiderFootEvent():
    """SpiderFootEvent object representing identified data and associated meta data.

    Attributes:
        generated (float): Timestamp of event creation time
        eventType (str): Event type, e.g. URL_FORM, RAW_DATA, etc.
        confidence (int): How sure are we of this data's validity, 0-100
        visibility (int): How 'visible' was this data, 0-100
        risk (int): How much risk does this data represent, 0-100
        module (str): Module from which the event originated
        data (str): Event data, e.g. a URL, port number, webpage content, etc.
        sourceEvent (SpiderFootEvent): SpiderFootEvent that triggered this event
        sourceEventHash (str): Hash of the SpiderFootEvent event that triggered this event
        hash (str): Unique SHA256 hash of the event, or "ROOT"
        moduleDataSource (str): Module data source
        actualSource (str): Source data of parent event
        __id (str): Unique ID of the event, generated using eventType, generated, module, and a random integer
    """

    _generated: float
    _eventType: str
    _confidence: int
    _visibility: int
    _risk: int
    _module: str
    _data: str
    _sourceEvent: SpiderFootEvent | None
    _sourceEventHash: str
    _moduleDataSource: str | None = None
    _actualSource: str | None = None
    __id: str

    # 1,365 in total
    def __init__(self, eventType: str, data: str, module: str, sourceEvent: SpiderFootEvent | None) -> None:
        """Initialize SpiderFoot event object.

        Args:
            eventType (str): Event type, e.g. URL_FORM, RAW_DATA, etc.
            data (str): Event data, e.g. a URL, port number, webpage content, etc.
            module (str): Module from which the event originated
            sourceEvent (SpiderFootEvent): SpiderFootEvent event that triggered this event
        """
        self._generated = time()
        self.data = data
        self.eventType = eventType
        self.module = module
        self.confidence = 100
        self.visibility = 100
        self.risk = 0
        self.sourceEvent = sourceEvent
        self.__id = f"{self.eventType}{self.generated}{self.module}{random.SystemRandom().randint(0, 99999999)}"

    # 3 in spiderfoot/event.py
    # 2 in spiderfoot/db.py
    @property
    def generated(self) -> float:
        """Timestamp of event creation time.

        Returns:
            float: timestamp of event creation time
        """
        return self._generated

    # 9 in spiderfoot/event.py
    # 4 in spiderfoot/db.py
    # 3 in spiderfoot/plugin.py
    # 2 in sfscan.py
    # 1 in test/unit/spiderfoot/test_spiderfootdb.py
    # … 4 others
    @property
    def eventType(self) -> str:
        """Event type.

        Returns:
            str: event type
        """
        return self._eventType

    # 5 in test/unit/spiderfoot/test_spiderfooteventpy
    # 4 in spiderfoot/event.py
    # 3 in spiderfoot/db.py
    # 1 in test/unit/spiderfoot/test_spiderfootdb.py
    @property
    def confidence(self) -> int:
        """How sure are we of this data's validity.

        Returns:
            int: confidence score (0 to 100).
        """
        return self._confidence

    # 5 in test/unit/spiderfoot/test_spiderfooteventpy
    # 4 in spiderfoot/event.py
    # 3 in spiderfoot/db.py
    # 1 in test/unit/spiderfoot/test_spiderfootdb.py
    @property
    def visibility(self) -> int:
        """How 'visible' was this data (0 to 100).

        Returns:
            int: visibility score (0 to 100).
        """
        return self._visibility

    # 5 in test/unit/spiderfoot/test_spiderfooteventpy
    # 4 in spiderfoot/event.py
    # 3 in spiderfoot/db.py
    # 1 in test/unit/spiderfoot/test_spiderfootdb.py
    @property
    def risk(self) -> int:
        """How much risk does this data represent.

        Returns:
            int: risk score (0 to 100).
        """
        return self._risk

    # 6 in spiderfoot/event.py
    # 2 in spiderfoot/db.py
    # 1 in test/unit/spiderfoot/test_spiderfootdb.py
    @property
    def module(self) -> str:
        return self._module

    # 7 in spiderfoot/event.py
    # 2 in spiderfoot/db.py
    # 2 in spiderfoot/plugin.py
    # 1 in test/unit/spiderfoot/test_spiderfootdb.py
    # … 3 others
    @property
    def data(self) -> str:
        return self._data

    # 7 in spiderfoot/event.py
    # 5 in spiderfoot/plugin.py
    # 2 in spiderfoot/db.py
    @property
    def sourceEvent(self) -> SpiderFootEvent | None:
        return self._sourceEvent

    # 2 in spiderfoot/db.py
    # 1 in spiderfoot/event.py
    # 1 in test/unit/spiderfoot/test_spiderfootevent.py
    @property
    def sourceEventHash(self) -> str:
        return self._sourceEventHash

    # 3 in spiderfoot/event.py
    # 2 in test/unit/spiderfoot/test_spiderfootevent.py
    # … 17 others
    @property
    def actualSource(self) -> str | None:
        return self._actualSource

    # 3 in spiderfoot/event.py
    # 2 in test/unit/spiderfoot/test_spiderfootevent.py
    # … 54 others
    @property
    def moduleDataSource(self) -> str | None:
        return self._moduleDataSource

    # 2 in spiderfoot/event.py
    # 2 in test/unit/spiderfoot/test_spiderfootevent.py
    # 1 in spiderfoot/db.py
    @property
    def hash(self) -> str:
        """Unique SHA256 hash of the event, or "ROOT".

        Returns:
            str: unique SHA256 hash of the event, or "ROOT"
        """
        if self.eventType == "ROOT":
            return "ROOT"

        digestStr = self.__id.encode('raw_unicode_escape')
        return hashlib.sha256(digestStr).hexdigest()

    @eventType.setter
    def eventType(self, eventType: str) -> None:
        """Event type.

        Args:
            eventType (str): type of data for this event

        Raises:
            TypeError: confidence type was invalid
            ValueError: confidence value was invalid
        """
        if not isinstance(eventType, str):
            raise TypeError(f"eventType is {type(eventType)}; expected str()")

        if not eventType:
            raise ValueError("eventType is empty")

        self._eventType = eventType

    @confidence.setter
    def confidence(self, confidence: int) -> None:
        """Event confidence.

        Args:
            confidence (int): How sure are we of this data's validity (0 to 100)

        Raises:
            TypeError: confidence type was invalid
            ValueError: confidence value was invalid
        """
        if not isinstance(confidence, int):
            raise TypeError(f"confidence is {type(confidence)}; expected int()")

        if not 0 <= confidence <= 100:
            raise ValueError(f"confidence value is {confidence}; expected 0 - 100")

        self._confidence = confidence

    @visibility.setter
    def visibility(self, visibility: int) -> None:
        """Event visibility.

        Args:
            visibility (int): How 'visible' was this data (0 to 100)

        Raises:
            TypeError: visibility type was invalid
            ValueError: visibility value was invalid
        """
        if not isinstance(visibility, int):
            raise TypeError(f"visibility is {type(visibility)}; expected int()")

        if not 0 <= visibility <= 100:
            raise ValueError(f"visibility value is {visibility}; expected 0 - 100")

        self._visibility = visibility

    @risk.setter
    def risk(self, risk: int) -> None:
        """Event risk.

        Args:
            risk (int): How much risk does this data represent (0 to 100)

        Raises:
            TypeError: risk type was invalid
            ValueError: risk value was invalid
        """
        if not isinstance(risk, int):
            raise TypeError(f"risk is {type(risk)}; expected int()")

        if not 0 <= risk <= 100:
            raise ValueError(f"risk value is {risk}; expected 0 - 100")

        self._risk = risk

    @module.setter
    def module(self, module: str) -> None:
        """Module which created the event.

        Args:
            module (str): module

        Raises:
            TypeError: module type was invalid
            ValueError: module value was invalid
        """
        if not isinstance(module, str):
            raise TypeError(f"module is {type(module )}; expected str()")

        if not module and self.eventType != "ROOT":
            raise ValueError("module is empty")

        self._module = module

    @data.setter
    def data(self, data: str) -> None:
        """Event data.

        Args:
            data (str): data

        Raises:
            TypeError: data type was invalid
            ValueError: data value was invalid
        """
        if not isinstance(data, str):
            raise TypeError(f"data is {type(data)}; expected str()")

        if not data:
            raise ValueError(f"data is empty: '{str(data)}'")

        self._data = data

    @sourceEvent.setter
    def sourceEvent(self, sourceEvent: SpiderFootEvent | None) -> None:
        """Source event which lead to this event.

        Args:
            sourceEvent (SpiderFootEvent): source event

        Raises:
            TypeError: sourceEvent type was invalid
        """
        # "ROOT" is a special "hash" reserved for elements with no parent,
        # such as targets provided via the web UI or CLI.
        if self.eventType == "ROOT":
            self._sourceEvent = None
            self._sourceEventHash = "ROOT"
            return

        # if not isinstance(sourceEvent, SpiderFootEvent):
        #     raise TypeError(f"sourceEvent is {type(sourceEvent)}; expected SpiderFootEvent()")

        self._sourceEvent = sourceEvent
        
        if self._sourceEvent is not None:
            self._sourceEventHash = self._sourceEvent.hash
        else:
            self._sourceEventHash = "ROOT"

    @actualSource.setter
    def actualSource(self, actualSource: str) -> None:
        self._actualSource = actualSource

    @moduleDataSource.setter
    def moduleDataSource(self, moduleDataSource: str) -> None:
        self._moduleDataSource = moduleDataSource

    # 2 in test/unit/spiderfoot/test_spiderfootevent.py
    # 1 in spiderfoot/event.py
    def asDict(self) -> dict:
        """Event object as dictionary.

        Returns:
            dict: event as dictionary
        """
        evtDict = {
            'generated': int(self.generated),
            'type': self.eventType,
            'data': self.data,
            'module': self.module,
            'source': ''
        }

        if self.sourceEvent is not None and self.sourceEvent.data is not None:
            evtDict['source'] = self.sourceEvent.data

        return evtDict

# end of SpiderFootEvent class

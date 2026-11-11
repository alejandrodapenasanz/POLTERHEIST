from abc import ABC, abstractmethod

from ..models import SessionLost, Unsupported


class Backend(ABC):
    def __init__(self, endpoint, network, config):
        self.endpoint = endpoint
        self.network = network
        self.config = config
        self.url = ""

    @abstractmethod
    def connect(self): ...

    @abstractmethod
    def play(self, url, media): ...

    @abstractmethod
    def get_status(self): ...

    def require_owned(self):
        status = self.get_status()
        if not self.url or status.url != self.url:
            raise SessionLost("Receiver content changed; no control command sent")
        return status

    def pause(self):
        raise Unsupported("Pause is not supported by this receiver")

    def resume(self):
        raise Unsupported("Resume is not supported by this receiver")

    @abstractmethod
    def stop(self): ...

    @abstractmethod
    def disconnect(self): ...

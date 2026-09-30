from ironwall.core.models import SecurityEvent
from ironwall.storage.database import Database


class EventBus:
    def __init__(self, database: Database) -> None:
        self.database = database
        self.listeners: list = []

    def emit(self, event: SecurityEvent) -> None:
        self.database.add_event(event)
        for listener in tuple(self.listeners):
            listener(event)

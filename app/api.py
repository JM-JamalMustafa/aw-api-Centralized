from app.settings import Settings

class ServerAPI:
    def __init__(self, db, testing) -> None:
        self.db = db
        self.settings = Settings(testing)
        self.testing = testing
        self.last_event = {}  # type: dict
        
    def get_setting(self, key):
        """Get a setting"""
        return self.settings.get(key, None)

    def set_setting(self, key, value):
        """Set a setting"""
        self.settings[key] = value
        return value

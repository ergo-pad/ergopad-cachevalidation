import logging

class Store:
    def __init__(self):
        self.data = {}

    def set(self, key: str, value):
        logging.info(f"Store.set::query for {key}")
        self.data[key] = value

    def get(self, key: str):
        logging.info(f"Store.get::query for {key}")
        if key in self.data:
            return self.data[key]
        logging.warning(f"Store.set::key not found {key}")
        return None

import requests
import time
import logging

from store import Store


class CachedRequests:
    cache = Store()
    config = {
        "default_ttl": 10  # 10 sec
    }

    @staticmethod
    def get(url):
        res = CachedRequests.cache.get(url)
        if (res and res["timestamp"] + CachedRequests.config["default_ttl"] > time.time()):
            # valid cached value
            logging.info(f"CachedRequests.get::cached return for {url}")
            return res["data"]
        else:
            try:
                logging.info(f"CachedRequests.get::polling for {url}")
                res = requests.get(url).json()
                CachedRequests.cache.set(url, {"timestamp": time.time(), "data": res})
                return res
            except Exception as e:
                logging.error(f"CachedRequests.get::{str(e)}")
                return None

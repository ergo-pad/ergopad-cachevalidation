import requests
import logging
import time
from urllib.parse import quote

import config
from store import Store
from cached_requests import CachedRequests


def get_jwt_token():
    try:
        url_auth = f"{config.ERGOPAD_API}/auth/token"
        username = config.ERGOPAD_USER
        password = config.ERGOPAD_PASSWORD
        headers = {"accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
        data = f"""grant_type=&username={quote(username)}&password={quote(password)}&scope=&client_id=&client_secret="""
        res = requests.post(url_auth, headers=headers, data=data)
        return res.json()["access_token"]
    except Exception as e:
        logging.error(f"get_jwt_token::{str(e)}")
        return None


def invalidate_cache(keys, access_token):
    try:
        url_invalidate_cache = f"{config.ERGOPAD_API}/util/forceInvalidateCache"
        headers = {"accept": "application/json"}
        json = {"keys": list(keys)}
        res = requests.post(url_invalidate_cache, headers=dict(headers, **{"Authorization": f"Bearer {access_token}"}), json=json)
        return res.json()
    except Exception as e:
        logging.error(f"invalidate_cache::{str(e)}")
        return None


def generate_keys(addresses):
    keys = []
    if len(addresses) == 0:
        return keys
    for address in addresses:
        address_key = f"get_staking_staked_addresses_{address}_balance_confirmed"
        keys.append(address_key)
    stake_token_key = f"get_staking_staked_token_boxes_{config.PAIDEIA_STAKE_TOKEN_ID}"
    keys.append(stake_token_key)
    return keys


def is_wallet_address(address):
    return 40 <= len(address) and len(address) <= 60


def get_new_addresses(old_transactions, new_transactions):
    old_transaction_ids = list(map(lambda x : x["id"], old_transactions))
    addresses = set()
    for transaction in new_transactions:
        if transaction["id"] not in old_transaction_ids:
            outputs = transaction["outputs"]
            for box in outputs:
                address = box["address"]
                if not is_wallet_address(address):
                    continue
                tokens = box["assets"]
                for token in tokens:
                    if token["name"] in config.TOKEN_NAMES:
                        addresses.add(address)
    return list(addresses)


class CacheInvalidatorService:
    def __init__(self):
        self.access_token = get_jwt_token()
        self.store = Store()


    def _loop(self):
        pool_url = f"{config.ERGO_EXPLORER_API}/addresses/{config.PAIDEIA_SMART_CONTRACT_ADDRESS}/transactions?offset=0&limit=30"
        res = CachedRequests.get(pool_url)
        transactions = res["items"]
        
        if str(self.store.get("transactions")) == str(transactions):
            logging.info(f"CacheInvalidatorService._loop::no new transactions detected")
            return

        logging.info(f"CacheInvalidatorService._loop::new transactions detected")
        old_transactions = []
        if self.store.get("transactions") != None:
            old_transactions = self.store.get("transactions")
        
        addresses = get_new_addresses(old_transactions, transactions)
        keys = generate_keys(addresses)
        if len(keys) != 0:
            logging.critical(f"CacheInvalidatorService._loop::invalidating the following keys: {str(keys)}")
            ret = invalidate_cache(keys, self.access_token)
            logging.critical(f"CacheInvalidatorService._loop::invalidated: {str(ret)}")

        self.store.set("transactions", transactions)


    def start(self):
        while True:
            try:
                self._loop()
            except Exception as e:
                logging.error(f"CacheInvalidatorService.start::{str(e)}")
                time.sleep(10)
                self.access_token = get_jwt_token()


if __name__ == "__main__":
    logging.info("main::starting CacheInvalidatorService")
    service = CacheInvalidatorService()
    service.start()

import requests
import logging
import time
from urllib.parse import quote

import config
from store import Store
from cached_requests import CachedRequests
from jwt_exception import JWTException


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
        if res.ok:
            return res.json()
        logging.warning(f"invalidate_cache::api failed")
    except Exception as e:
        logging.error(f"invalidate_cache::{str(e)}")
        return None


def is_wallet_address(address):
    return 40 <= len(address) and len(address) <= 60


def generate_keys_staking(addresses, stake_config):
    keys = []
    if len(addresses) == 0:
        return keys
    for address in addresses:
        address_key = f"get_staking_staked_addresses_{address}_balance_confirmed"
        keys.append(address_key)
    stake_token_key = f"get_staking_staked_token_boxes_{stake_config['stake_token_id']}"
    keys.append(stake_token_key)
    return keys


def get_new_addresses_staking(old_transactions, new_transactions, stake_config):
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
                    if token["name"] in stake_config["token_names"]:
                        addresses.add(address)
    return list(addresses)


class CacheInvalidatorService:
    def __init__(self):
        self.access_token = get_jwt_token()
        self.store = Store()

    # _loop over multiple smart contract addresses
    # passed in as config
    def _loop_staking(self, stake_config):
        pool_url = f"{config.ERGO_EXPLORER_API}/addresses/{stake_config['smart_contract_address']}/transactions?offset=0&limit=30"
        res = CachedRequests.get(pool_url)
        transactions = res["items"]

        if str(self.store.get(f"transactions_{stake_config['name']}")) == str(transactions):
            logging.info(f"CacheInvalidatorService._loop_staking::no new transactions detected for {stake_config['name']}")
            return

        logging.info(f"CacheInvalidatorService._loop_staking::new transactions detected for {stake_config['name']}")
        old_transactions = []
        if self.store.get(f"transactions_{stake_config['name']}") != None:
            old_transactions = self.store.get(f"transactions_{stake_config['name']}")

        addresses = get_new_addresses_staking(old_transactions, transactions, stake_config)
        keys = generate_keys_staking(addresses, stake_config)
        if len(keys) != 0:
            logging.critical(f"CacheInvalidatorService._loop_staking::invalidating the following keys: {str(keys)}")
            ret = invalidate_cache(keys, self.access_token)
            if ret == None:
                raise JWTException("CacheInvalidatorService._loop_staking::jwt token expired")
            logging.critical(f"CacheInvalidatorService._loop_staking::invalidated: {str(ret)}")

        self.store.set(f"transactions_{stake_config['name']}", transactions)


    def start(self):
        while True:
            try:
                for stake_config in config.STAKING_TOKENS:
                    try:
                        self._loop_staking(stake_config)
                    except JWTException as e:
                        raise e
                    except Exception as e:
                        logging.error(f"CacheInvalidatorService.start::{str(e)}")
            except Exception as e:
                logging.error(f"CacheInvalidatorService.start::{str(e)}")
                time.sleep(10)
                self.access_token = get_jwt_token()


if __name__ == "__main__":
    logging.info("main::starting CacheInvalidatorService")
    service = CacheInvalidatorService()
    service.start()

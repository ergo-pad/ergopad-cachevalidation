# ergopad-cache-invalidation
- cache invalidation and other performance tweaks

## Quick Start
- create a .env file with ergopad admin username and password
```
$ pip3 install -r requirements.txt
$ python3 main.py
```

## Flows
- Poll for changes on the smart contract addresses
- Invalidates redis cache keys on transaction confirmation

## Support
Join the Ergopad `#development` channel on discord

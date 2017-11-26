# Hybrid

Hybrid encription communication protocool

## Using:
**RSA** and **AES** for hybrid encryption.

## How to use:
It is configured for default to make a local test and **for now** it only tests and secures the connection.
**client.py** and **server.py** share a 32 bytes **AES** keys with an **RSA** assimetric encryption.
When the **secure** key sharing is done, they both print the two **AES** keys to make sure the sharing is done correctly.


## Tip:
If you change the ```localhost``` in ```c = Client(("localhost",4777))``` on **client.py** you can try non local communication.

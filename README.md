# Hybrid

Hybrid encription communication protocool

## Using:
**RSA** and **AES** for hybrid encryption.

## How to use:
It is configured for default to make a local test and **for now** it only tests and secures the connection.
**client.py** and **server.py** share a 32 bytes **AES** keys with an **RSA** asymmetric encryption.
When the **secure** key sharing is done, you can send encrypted messages from client to server.


## Tip:
If you change the ```localhost``` in ```c = Client(("localhost",4777))``` on **client.py** you can try non local communication.

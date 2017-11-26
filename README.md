# Hybrid

Hybrid encription communication protocool

## Using:
**RSA** and **AES** for hybrid encryption.

## How to use:
It is configured for local test for default and for now it only tests and secures the connection.
**client.py** and **server.py** share a 32 bytes **AES** keys with an **RSA** assimetric encryption.
When the **secure** key sharing is done, they both print the two **AES** keys to make sure the sharing is done correctly.

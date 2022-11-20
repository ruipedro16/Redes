# Redes

## Valid Certificate

```shell
./responder.py
./client.py --host sigarra.up.pt --port 443
```

```shell
./responder.py
./client.py --cert github.pem
```

## Revoked Certificate

```shell
./responder.py
./client.py --host aaacertificateservices.comodoca.com --port 444
```

## Expired Certificate

```shell
./responder.py
./client.py --host aaacertificateservices.comodoca.com --port 442
```

## Self-Signed Cerificate (Error)

```shell
openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -sha256 -days 365 -subj '/CN=localhost'
./responder.py
./client.py --cert cert.pem
```
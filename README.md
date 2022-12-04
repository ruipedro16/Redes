# Redes

## OCSP

### Valid Certificate

```shell
./server.py
./client.py --host sigarra.up.pt --port 443
```

```shell
./server.py
./client.py --cert github.pem
```

### Revoked Certificate

```shell
./server.py
./client.py --host aaacertificateservices.comodoca.com --port 444
```

### Expired Certificate

```shell
./server.py
./client.py --host aaacertificateservices.comodoca.com --port 442
```

### Self-Signed Certificate (Should fail)

```shell
openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -sha256 -days 365 -subj '/CN=localhost'
# to see the certificate
openssl x509 -in cert.pem -text
./server.py
./client.py --cert cert.pem
```

## Dangerous Delegated Responder Certificate Problem

```shell
./delegated.py -o out
./test.sh
```

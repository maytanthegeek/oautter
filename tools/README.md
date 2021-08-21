# Tools

This directory includes instructions as well as tools for generating auxiliary files for the server.

## Generating private and public keys

Use one of the following commands to generate a private and public key pair.

#### With OpenSSL
```
> openssl genrsa -out private.pem 2048
> openssl rsa -in private.pem -pubout -out public.pem
```

#### With ssh-keygen
```
> ssh-keygen -t rsa -b 2048 -f private.pem -N "" -m PEM
> ssh-keygen -f private.pem -e -m PEM > public.pem
> rm private.pem.pub
```

## Generating JWKS from public key

Use the `pem-jwks` utility provided in this directory to generate a JWKS file from the public key.
```
> ./pem-jwks --kid myownkeyset public.pem > public.json
```

## Placing all files in a directory for the server to find

Ther server looks for the key files and JWKS file in the directory `keys`.

If you generated the key files and JWKS file in the current directory, you can simply move them to the `keys` directory.
```
> mkdir ../keys
> mv private.pem public.pem public.json ../keys
```
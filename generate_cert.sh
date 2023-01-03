#!/bin/bash

openssl genrsa -des3 -passout pass:ucl0v13 -out tls_cert.pass.key 2048
openssl rsa -passin pass:ucl0v13 -in tls_cert.pass.key -out tls_cert.key
rm tls_cert.pass.key
openssl req -new -key tls_cert.key -out tls_cert.csr \
    -subj "/C=UK/ST=ElNiak/L=Leamington/O=OrgName/OU=IT Department/CN=ivy-visualizer"
openssl x509 -req -days 365 -in tls_cert.csr -signkey tls_cert.key -out tls_cert.crt


# TODO add this cert to browser

openssl pkcs12 -export -in tls_cert.crt -inkey tls_cert.key -out tls_cert.p12
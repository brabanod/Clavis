# Clavis

Clavis is a framework for generating and validating software licenses for your app.


Generate private key using
`openssl genrsa -out private.pem 2048`

Generate public key using
`openssl rsa -in private.pem -outform PEM -pubout -out public.pem`

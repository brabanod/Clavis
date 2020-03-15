# Clavis

Clavis is a framework for easily generating and validating software licenses for your app.


## How to license your app
To use Clavis for license managing, you need to follow these steps:
* Generate RSA key pair (once)
* In a seperate application/command line tool/server app: Generate licenses with Clavis for your users using the private key
* In your app: Validate licenses using Clavis at app startup using the public key. The public key needs to be shipped with the app.

**Important:** Don't share your private key, this is the one you keep. Also make sure you don't loose it otherwise you will need to update your app with a new public key, in order to issue new licenses. 

Read more on licensing an application [here](https://stackoverflow.com/a/14427572/3272409).




## Usage


### Generate RSA Keys
To use Clavis, you need a public an a private RSA Key. You can generate them using the `openssl` command line utility.

Generate private key using
```
openssl genrsa -out private.pem 2048
```

Generate public key using
```
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```


### Generate Licenses
To generate a license, you will need the private key and a message, which will be encrypted in the license. This can be the name or the email or a combination of both of the person, for whom the license was issued. The license can be limited by specifying an expiration date. If no expiration date is specified, then the license is unlimited.
```swift
let plaintext = "John Doe"
let license = try Clavis.Generator.license(privateKey: privateKey, publicKey: publicKey, keyMessage: plaintext)

let todayPlusOneDay = Date().addingTimeInterval(24*3600.0)
let licenseLimited = try Clavis.Generator.license(privateKey: privateKey, publicKey: publicKey, keyMessage: plaintext, expirationDate: todayPlusOneDay)
```


### Validate Licenses
To validate a license, you need to provide the public key, the license and the message. The `isValid` method will then check, if the given license is equal to the given plaintext and thus valid.
```swift
let license = "zHFGj6rhT9Kxb5..."
let plaintext = "John Doe"
let validation = try Clavis.Validator.isValid(license: license, plaintext: plaintext, publicKey: publicKey)
```

In order to have a better user experience, `isValid` will store the license in the keychain, so that the user doesn't have to type it in at every app startup. Use `hasValidLicense` to check, if there is a valid license stored in the keychain.
```swift
if try Clavis.Validator.hasValidLicense(publicKey: publicKey) {
    // Start app
} else {
    // Ask for license
}
```

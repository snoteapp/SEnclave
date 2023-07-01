# SEnclave

Core data encryption for https://snote.app


## Import into your web application
```javascript
<script src="senclave.min.js"></script>
```


## Basic Usage
```javascript
// Create Local Account And Login
await SEnclave.signup('user@domain.com', 'password');

// Generate symmetric key encrypted using the account private key
let ekey=await SEnclave.generateEncryptedKey();

// Create secure enclave using the encrypted symmetric key
let se=await SEnclave.create({ekey:ekey});

// Encrypt data
let edata=await se.encrypt("hello world");

// Decrypt data
let data=await se.decrypt(edata);
```


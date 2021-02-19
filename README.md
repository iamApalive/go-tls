# TLS Experiment

Minimal TLS 1.2 Client Handshake implementation in Go. The project was implemented for academic purpose.

## Support
- The project can be easily extended with more cipher suites. At the moment it has support only for `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`.
- Each TLS structure can be visualized in JSON format.

## Workflow
1. Creates `Client Hello`
2. Receives and parses `Server Hello`, `Server Certificate`, `Server Key Exchange`, `Server Hello Done`
3. Generates and sends `Client Key Exchange`
4. Calculates `Client Encryption Keys`
5. Sends `Client Change Cipher Spec`, `Client Handshake Finished`
6. Receives and parses `Server Change Cipher Spec`, `Server Handshake Finished`
7. Encrypts a raw HTTP request and sends `Client Application Data`
8. Receives `Server Application Data`
9. Decrypts the HTTP response

### Links
- [TLS Protocol Version 1.2 Specs](https://tools.ietf.org/html/rfc5246)
- [Illustrated TLS messages](https://tls.ulfheim.net/)

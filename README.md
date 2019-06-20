# Node OCSP bug reproduction

### Requirements

- Node 12
- OpenSSL 1.1.1

### Run the code

- `npm test`

### Result

The `OCSPRequest` event does not work when a custom ecdhCurve is used.

```
> node ocsp_bug_repro.js

running testTlsServerWithCurves
Server did not send OCSP response with TLS 1.3
testTlsServerWithCurves : Test failed

running testTlsServerWithoutCurves
testTlsServerWithoutCurves : OK

```

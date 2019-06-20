const tls = require('tls');
const fs = require('fs');
const { exec } = require('child_process');

const LOCAL_PORT = 7897;
const TLS_VERSION_OPTIONS = {
  '1.1': '-tls1_1',
  '1.2': '-tls1_2',
  '1.3': '-tls1_3',
};
const NO_RESPONSE_SENT = 'OCSP response: no response sent';
const RESPONSE_PARSE_ERROR = 'OCSP response: response parse error';
const RESPONSE_DATA_RE = /OCSP response:.*OCSP Response Data:/s; // dot matches newline

const ecdhCurve = 'brainpoolP384r1:brainpoolP512r1:secp384r1:secp521r1:sect409k1:sect409r1:sect571k1:sect571r1';

function terminus(promise) {
  promise.catch((err) => setTimeout(() => { throw err; }));
}

function receivesOCSPResponse(host, port, tlsVersion) {
  const tlsOption = TLS_VERSION_OPTIONS[tlsVersion] || '';
  return new Promise((resolve, reject) => {
    const cmd = `echo EXIT | openssl s_client -connect ${host}:${port} -CAfile server-cert.pem -status ${tlsOption}`;
    exec(cmd, (err, stdout, stderr) => {
      if (stdout.includes(NO_RESPONSE_SENT)) {
        resolve(false);
      } else if (stdout.includes(RESPONSE_PARSE_ERROR)) {
        resolve(true);
      } else if (RESPONSE_DATA_RE.test(stdout)) {
        resolve(true);
      } else {
        console.warn(stdout);
        reject(new Error('Invalid response from OpenSSL'));
      }
    });
  });
}

function addOCSPHandler(tlsServer) {
  tlsServer.on('OCSPRequest', (cert, issuer, cb) => {
    setTimeout(() => cb(null, Buffer.from('mock ocsp data')), 3);
  });
}

async function runServerTests(testName) {
  console.log('running', testName);
  let hasError = false;
  // test TLS 1.3
  if (!await receivesOCSPResponse('localhost', LOCAL_PORT, '1.3')) {
    console.warn('Server did not send OCSP response with TLS 1.3');
    hasError = true;
  }
  // test TLS 1.2
  if (!await receivesOCSPResponse('localhost', LOCAL_PORT, '1.2')) {
    console.warn('Server did not send OCSP response with TLS 1.2');
    hasError = true;
  }
  if (hasError) console.log(testName, ': Test failed\n');
  else console.log(testName, ': OK\n');
}

async function testTlsServerWithCurves() {
  const options = {
    // openssl req -x509 -newkey rsa:2048 -keyout server-key.pem -out server-cert.pem -days 365 -nodes
    key: fs.readFileSync('server-key.pem'),
    cert: fs.readFileSync('server-cert.pem'),
    ecdhCurve,
  };
  const server = tls.createServer(options);
  addOCSPHandler(server);
  server.listen(LOCAL_PORT);

  await runServerTests('testTlsServerWithCurves');
  server.close();
}

async function testTlsServerWithoutCurves() {
  const options = {
    // openssl req -x509 -newkey rsa:2048 -keyout server-key.pem -out server-cert.pem -days 365 -nodes
    key: fs.readFileSync('server-key.pem'),
    cert: fs.readFileSync('server-cert.pem'),
  };
  const server = tls.createServer(options);
  addOCSPHandler(server);
  server.listen(LOCAL_PORT);

  await runServerTests('testTlsServerWithoutCurves');
  server.close();
}

async function allTests() {
  await testTlsServerWithCurves();
  await testTlsServerWithoutCurves();
  process.exit();
}

terminus(allTests());


import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ProductAccountTxPayload, HostAccountGetRequest } from '@parity/truapi';

// Independent host-api 0.9.1 codecs match the live gateway's TruAPI 0.13.1
// Index(u32) | Raw(bytes32) account selector; verified 2026-09-09.
const { CreateTransactionV1_request } = await import(new URL(
  './protocol/v1/createTransaction.js', import.meta.resolve('@novasamatech/host-api'),
));
const bytes = hex => Uint8Array.from(Buffer.from(hex.slice(2), 'hex'));
const genesisHash = '0xd6eec26135305a8ad257a20d003357284c8aa03d0bdb2b357ab0a22371e11ef2';

test('gateway decodes the product signer, network, call and extensions unchanged', () => {
  const request = {
    signer: { dotNsIdentifier: 'example-door.dot', derivationIndex: { tag: 'Index', value: 0 } },
    genesisHash,
    callData: '0x01020304',
    extensions: [{ id: 'CheckGenesis', extra: '0x', additionalSigned: genesisHash }],
    txExtVersion: 0,
  };
  const encoded = ProductAccountTxPayload.enc(request);
  const expected = {
    signer: ['example-door.dot', { tag: 'Index', value: 0 }],
    genesisHash,
    callData: bytes(request.callData),
    extensions: [{ id: 'CheckGenesis', extra: bytes('0x'), additionalSigned: bytes(genesisHash) }],
    txExtVersion: 0,
  };
  assert.deepEqual(CreateTransactionV1_request.dec(encoded), expected);
  assert.deepEqual(encoded, CreateTransactionV1_request.enc(expected));
});

const { AccountGetV1_request } = await import(new URL(
  './protocol/v1/accounts.js', import.meta.resolve('@novasamatech/host-api'),
));
test('gateway decodes the app account request with a tagged index', () => {
  const id = { dotNsIdentifier: 'example-door.dot', derivationIndex: { tag: 'Index', value: 0 } };
  const encoded = HostAccountGetRequest.enc({ productAccountId: id });
  const expected = ['example-door.dot', { tag: 'Index', value: 0 }];
  assert.deepEqual(AccountGetV1_request.dec(encoded), expected);
  assert.deepEqual(encoded, AccountGetV1_request.enc(expected));
});
test('old plain-u32 account request reproduces the current host decoding failure', () => {
  const name = new TextEncoder().encode('example-door.dot');
  const oldRequest = Uint8Array.of(name.length << 2, ...name, 0, 0, 0, 0);
  assert.throws(() => AccountGetV1_request.dec(oldRequest));
});

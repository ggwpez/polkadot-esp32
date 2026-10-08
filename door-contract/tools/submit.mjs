// Chain-aware signing uses the same PAPI descriptors as CDM 0.9.0.
import { readFileSync } from 'node:fs';
import { createClient, Enum } from 'polkadot-api';
import { getWsProvider } from 'polkadot-api/ws';
import { getPolkadotSigner } from 'polkadot-api/signer';
import { sr25519CreateDerive } from '@polkadot-labs/hdkd';
import { mnemonicToEntropy, entropyToMiniSecret, ss58Address } from '@polkadot-labs/hdkd-helpers';
import { devnet_asset_hub } from '@parity/product-sdk-descriptors/devnet-asset-hub';
const key = sr25519CreateDerive(entropyToMiniSecret(mnemonicToEntropy(process.env.DOOR_MNEMONIC)))('');
const signer = getPolkadotSigner(key.publicKey, 'Sr25519', key.sign);
const client = createClient(getWsProvider('wss://asset-hub-paseo-rpc.n.dwellir.com'));
const api = client.getTypedApi(devnet_asset_hub);
const origin = process.env.DOOR_ADMIN_ADDRESS;
const json = v => JSON.stringify(v, (_, x) => typeof x === 'bigint' ? x.toString() : x);
try {
  if (ss58Address(key.publicKey) !== origin) throw Error('Signing key does not match configured admin');
  if ((await client.getChainSpecData()).genesisHash !== '0xd6eec26135305a8ad257a20d003357284c8aa03d0bdb2b357ab0a22371e11ef2')
    throw Error('Wrong Asset Hub genesis');
  const [mode, target, input] = process.argv.slice(2);
  if (!['map', 'deploy', 'call'].includes(mode)) throw Error('Expected map, deploy or call');
  let tx;
  if (mode === 'map') tx = api.tx.Revive.map_account();
  else {
    const data = new Uint8Array(Buffer.from((input ?? '').replace(/^0x/, ''), 'hex'));
    const code = mode === 'deploy' ? new Uint8Array(readFileSync(target)) : undefined;
    const dry = mode === 'deploy'
      ? await api.apis.ReviveApi.instantiate(origin, 0n, undefined, undefined, Enum('Upload', code), data, undefined, {at:'best'})
      : await api.apis.ReviveApi.call(origin, target, 0n, undefined, undefined, data, {at:'best'});
    if (!dry.result.success || ((dry.result.value.flags ?? dry.result.value.result?.flags ?? 0) & 1))
      throw Error('Contract dry-run rejected: ' + json(dry.result));
    const weight_limit = {ref_time: dry.weight_required.ref_time * 120n / 100n, proof_size: dry.weight_required.proof_size * 120n / 100n};
    const storage_deposit_limit = dry.storage_deposit.type === 'Charge' ? dry.storage_deposit.value * 120n / 100n : 0n;
    console.log('Dry-run passed: ' + json({weight_limit, storage_deposit_limit}));
    tx = mode === 'deploy'
      ? api.tx.Revive.instantiate_with_code({value:0n, weight_limit, storage_deposit_limit, code, data, salt:undefined})
      : api.tx.Revive.call({dest:target, value:0n, weight_limit, storage_deposit_limit, data});
  }
  const result = await tx.signAndSubmit(signer);
  if (!result.ok) throw Error('Transaction rejected: ' + json(result.dispatchError));
  console.log('Finalized transaction: ' + result.txHash);
  if (mode === 'deploy') {
    const event = api.event.Revive.Instantiated.filter(result.events)[0];
    if (!event) throw Error('No Instantiated event; inspect transaction before retrying');
    console.log('Contract address: ' + event.payload.contract);
  }
} catch (e) {
  console.error(String(e).replaceAll(process.env.DOOR_MNEMONIC, '[REDACTED]'));
  process.exitCode = 1;
} finally { client.destroy(); }

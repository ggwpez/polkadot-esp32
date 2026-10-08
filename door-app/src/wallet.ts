import { HostProvider, SignerManager, type SignerAccount, type SignerState } from '@parity/product-sdk/wallet';

export function createWalletManager() {
  return new SignerManager({
    dappName: 'example-door.dot',
    // There is one app account; selecting it must not wait for host storage.
    persistence: null,
    createProvider: () => new HostProvider({
      productAccount: { dotNsIdentifier: 'example-door.dot', requestName: false },
      requestChainSubmitPermission: false,
    }),
  });
}

type Manager = Pick<SignerManager, 'connect' | 'getState' | 'getSigner' | 'subscribe' | 'destroy'>;

export class WalletSession {
  private manager: Manager | undefined;
  private connection: Promise<SignerAccount> | undefined;
  private unsubscribe: (() => void) | undefined;
  private cancel: (() => void) | undefined;
  private destroyed = false;
  private readonly makeManager: () => Manager;
  private readonly onState: (state: SignerState) => void;
  private readonly timeoutMs: number;

  constructor(onState: (state: SignerState) => void, makeManager: () => Manager = createWalletManager, timeoutMs = 20_000) {
    this.onState = onState;
    this.makeManager = makeManager;
    this.timeoutMs = timeoutMs;
  }

  getSigner() { return this.manager?.getSigner() ?? null; }

  connect(): Promise<SignerAccount> {
    if (this.destroyed) return Promise.reject(Error('Wallet session is closed.'));
    if (this.connection) return this.connection;
    const selected = this.manager?.getState().selectedAccount;
    if (selected) return Promise.resolve(selected);
    this.release();
    const manager = this.makeManager();
    this.manager = manager;
    this.unsubscribe = manager.subscribe(state => {
      if (this.manager === manager) this.onState(state);
    });
    let timer: ReturnType<typeof setTimeout>;
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(Error('Your wallet did not respond in time. Check that you are signed in to the Polkadot host, then click Connect wallet to retry.')), this.timeoutMs);
      this.cancel = () => reject(Error('Wallet session is closed.'));
    });
    const request = manager.connect().then(result => {
      // The SDK does not cancel every host call. Dispose late results so an
      // expired attempt cannot select an account or replace a newer session.
      if (this.manager !== manager) {
        manager.destroy();
        throw Error('This wallet connection expired.');
      }
      if (!result.ok) throw result.error;
      const account = manager.getState().selectedAccount;
      if (!account) throw Error('Sign in to your wallet, then connect to see your funding address.');
      return account;
    });
    const connection = Promise.race([request, deadline]).catch(error => {
      if (this.manager === manager) this.release();
      throw error;
    }).finally(() => {
      clearTimeout(timer);
      if (this.connection === connection) {
        this.connection = undefined;
        this.cancel = undefined;
      }
    });
    this.connection = connection;
    return connection;
  }

  private release() {
    this.unsubscribe?.();
    this.unsubscribe = undefined;
    const previous = this.manager;
    this.manager = undefined;
    previous?.destroy();
  }

  destroy() {
    this.destroyed = true;
    this.cancel?.();
    this.release();
  }
}

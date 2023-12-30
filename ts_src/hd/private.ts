import {
  bytesToHex as toHex,
  hexToBytes as fromHex,
} from "@noble/hashes/utils";
import { ZERO_KEY, ZERO_PRIVKEY } from "./common";
import {
  Keyring,
  PrivateKeyOptions,
  SerializedHDKey,
  Hex,
  ToSignInput,
} from "./types";
import { BaseWallet } from "./base";
import * as tinysecp from "bells-secp256k1";
import { mnemonicToSeed } from "bip39";
import ECPairFactory, { ECPairInterface } from "belpair";
import { Psbt } from "belcoinjs-lib";
import HDKey from "browser-hdkey";
import { sha256 } from "@noble/hashes/sha256";

const ECPair = ECPairFactory(tinysecp);

const hdPathString = "m/44'/0'/0'/0";

class HDPrivateKey extends BaseWallet implements Keyring<SerializedHDKey> {
  childIndex: number = 0;
  privateKey: Buffer = ZERO_PRIVKEY;
  publicKey = ZERO_KEY;
  accounts: ECPairInterface[] = [];

  private seed?: Uint8Array;
  private hdWallet?: HDKey;
  private root?: HDKey;
  private hdPath: string = hdPathString;

  constructor(options?: PrivateKeyOptions) {
    super();
    if (options) this.fromOptions(options);
  }

  changeHdPath(hdPath: string) {
    this.hdPath = hdPath;
    this.root = this.hdWallet?.derive(this.hdPath);

    this.accounts = [];
  }

  signTypedData(address: string, typedData: Record<string, unknown>) {
    return this.signMessage(address, JSON.stringify(typedData));
  }

  exportPublicKey(address: string) {
    const account = this.findAccount(address);
    return account.publicKey.toString("hex");
  }

  verifyMessage(address: string, text: string, sig: string) {
    const account = this.findAccount(address);
    const hash = sha256(text);
    return account.verify(Buffer.from(hash), Buffer.from(sig, "base64"));
  }

  getAccounts() {
    const accounts = this.accounts.map((w) => {
      return this.getAddress(w.publicKey)!;
    });
    return [this.getAddress(this.publicKey!)!, ...accounts];
  }

  addAccounts(number: number = 1) {
    let count = number;
    let currentIdx = this.accounts.length;
    const newAddresses: string[] = [];

    while (count) {
      const wallet = this._addressFromIndex(currentIdx);
      newAddresses.push(this.getAddress(wallet.publicKey)!);

      currentIdx++;
      count--;
    }

    return newAddresses;
  }

  private findAccount(account: Hex): ECPairInterface {
    if (this.getAddress(this.publicKey) === account) {
      return ECPair.fromPrivateKey(this.privateKey);
    }
    const foundAccount = this.accounts.find(
      (f) => this.getAddress(f.publicKey) === account
    );
    if (foundAccount !== undefined) {
      return foundAccount;
    }
    throw new Error(
      `HDPrivateKey: Account with address ${account} not founded`
    );
  }

  private findAccountByPk(publicKey: string): ECPairInterface {
    if (this.publicKey?.toString("hex") === publicKey) {
      return ECPair.fromPrivateKey(this.privateKey);
    }
    const foundAccount = this.accounts.find(
      (f) => f.publicKey.toString("hex") === publicKey
    );
    if (foundAccount !== undefined) {
      return foundAccount;
    }
    throw new Error(
      `HDPrivateKey: Account with public key ${publicKey} not founded`
    );
  }

  exportAccount(address: Hex) {
    const account = this.findAccount(address);
    return account.toWIF();
  }

  signPsbt(psbt: Psbt, inputs: ToSignInput[]) {
    let account: ECPairInterface | undefined;

    inputs.map((i) => {
      account = this.findAccountByPk(i.publicKey);
      psbt.signInput(i.index, account, i.sighashTypes);
    });

    psbt.finalizeAllInputs();
  }

  signMessage(address: Hex, text: string) {
    const account = this.findAccount(address);
    const hash = sha256(text);
    return account.sign(Buffer.from(hash)).toString("base64");
  }

  signPersonalMessage(address: Hex, message: Hex) {
    return this.signMessage(address, message);
  }

  async fromOptions(options: PrivateKeyOptions) {
    this.fromSeed(Buffer.from(options.seed));
    return this;
  }

  static fromOptions(options: PrivateKeyOptions) {
    return new this().fromOptions(options);
  }

  fromSeed(seed: Uint8Array) {
    this.childIndex = 0;
    this.seed = seed;
    this.hdWallet = HDKey.fromMasterSeed(Buffer.from(seed));
    this.root = this.hdWallet.derive(this.hdPath);

    this.privateKey = this.root.privateKey!;
    this.publicKey = this.root.publicKey!;

    return this;
  }

  static fromSeed(seed: Uint8Array): HDPrivateKey {
    return new this().fromSeed(seed);
  }

  async fromMnemonic(
    mnemonic: string,
    passphrase?: string
  ): Promise<HDPrivateKey> {
    const seed = await mnemonicToSeed(mnemonic, passphrase ?? "bells");
    this.fromSeed(seed);

    return this;
  }

  static fromMnemonic(
    mnemonic: string,
    passphrase?: string
  ): Promise<HDPrivateKey> {
    return new this().fromMnemonic(mnemonic, passphrase);
  }

  fromPhrase(phrase: string): HDPrivateKey {
    this.fromMnemonic(phrase);
    return this;
  }

  static fromPhrase(phrase: string): HDPrivateKey {
    return new this().fromPhrase(phrase);
  }

  fromPrivateKey(_key: Uint8Array) {
    throw new Error("Method not allowed for HDPrivateKey.");
  }

  static fromPrivateKey(key: Uint8Array) {
    return new this().fromPrivateKey(key);
  }

  private getChildCount(): number {
    return this.accounts.length;
  }

  serialize() {
    if (this.childIndex !== 0)
      throw new Error("You should use only root wallet to serializing");
    return {
      numberOfAccounts: this.getChildCount(),
      seed: toHex(this.seed!),
      addressType: this.addressType!,
    };
  }

  static deserialize(opts: SerializedHDKey) {
    if (opts.numberOfAccounts === undefined || !opts.seed) {
      throw new Error(
        "HDPrivateKey: Deserialize method cannot be called with an opts value for numberOfAccounts and no seed"
      );
    }

    const root = HDPrivateKey.fromSeed(fromHex(opts.seed));
    root.addressType = opts.addressType;

    if (!opts.numberOfAccounts) return root;

    root.addAccounts(opts.numberOfAccounts);
    return root;
  }

  deserialize(state: SerializedHDKey) {
    return HDPrivateKey.deserialize(state);
  }

  private _addressFromIndex(i: number): ECPairInterface {
    if (!this.accounts[i]) {
      const child = this.root?.deriveChild(i);
      const ecpair = ECPair.fromPrivateKey(
        Buffer.from((child as any).privateKey)
      );
      this.accounts.push(ecpair);
    }

    return this.accounts[i];
  }
}

export default HDPrivateKey;

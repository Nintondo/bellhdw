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
import * as secp from "secp256k1";
import * as tinysecp from "bells-secp256k1";
import { mnemonicToSeed } from "bip39";
// @ts-ignore
import ECPairFactory, { ECPairInterface } from "belpair";
import { Psbt, networks } from "belcoinjs-lib";

const HARDENED_OFFSET = 0x80000000;
const MASTER_SECRET = Buffer.from("Bitcoin seed", "utf8");

const ECPair = ECPairFactory(tinysecp);

const crypto = require("crypto");
const hdPathString = "m/44'/0'/0'/0";

const assert = (expression: any, message: string) => {
  if (!expression) {
    throw new Error(message);
  }
};

const BITCOIN_VERSIONS = { private: 0x0488ade4, public: 0x0488b21e };

class HDKey {
  private versions = BITCOIN_VERSIONS;
  publicKey?: Buffer;
  privateKey?: Buffer;
  chainCode?: Buffer;

  private depth = 0;

  constructor(versions?: { private: number; public: number }) {
    if (versions) {
      this.versions = versions;
    }
  }

  deriveChild(index: number): HDKey {
    var isHardened = index >= HARDENED_OFFSET;
    var indexBuffer = Buffer.allocUnsafe(4);
    indexBuffer.writeUInt32BE(index, 0);

    var data;

    if (isHardened) {
      assert(this.privateKey, "Could not derive hardened child key");

      var pk = this.privateKey;
      var zb = Buffer.alloc(1, 0);
      pk = Buffer.concat([zb, pk!]);

      data = Buffer.concat([pk, indexBuffer]);
    } else {
      data = Buffer.concat([this.publicKey!, indexBuffer]);
    }

    var I = crypto.createHmac("sha512", this.chainCode).update(data).digest();
    var IL = I.slice(0, 32);
    var IR = I.slice(32);

    var hd = new HDKey(this.versions);

    if (this.privateKey) {
      try {
        hd.privateKey = Buffer.from(
          secp.privateKeyTweakAdd(Buffer.from(this.privateKey), IL)!
        );
      } catch (err) {
        return this.deriveChild(index + 1);
      }
    } else {
      try {
        hd.publicKey = Buffer.from(
          secp.publicKeyTweakAdd(Buffer.from(this.publicKey!), IL, true)!
        );
      } catch (err) {
        return this.deriveChild(index + 1);
      }
    }

    hd.chainCode = IR;
    hd.depth = this.depth + 1;

    return hd;
  }

  static fromMasterSeed(seedBuffer: Buffer): HDKey {
    const I = crypto
      .createHmac("sha512", MASTER_SECRET)
      .update(seedBuffer)
      .digest();
    const IL = I.slice(0, 32);
    const IR = I.slice(32);

    const hdkey = new HDKey();
    hdkey.chainCode = IR;
    hdkey.privateKey = IL;

    return hdkey;
  }

  derive(path: string) {
    if (path === "m" || path === "M" || path === "m'" || path === "M'") {
      return this;
    }

    let entries = path.split("/");
    let hdkey: HDKey = this;
    entries.forEach(function (c, i) {
      if (i === 0) {
        assert(/^[mM]{1}/.test(c), 'Path must start with "m" or "M"');
        return;
      }

      const hardened = c.length > 1 && c[c.length - 1] === "'";
      let childIndex = parseInt(c, 10); // & (HARDENED_OFFSET - 1)
      assert(childIndex < HARDENED_OFFSET, "Invalid index");
      if (hardened) childIndex += HARDENED_OFFSET;

      hdkey = hdkey.deriveChild(childIndex);
    });

    return hdkey;
  }
}

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
    return account.verify(Buffer.from(text), Buffer.from(sig, "base64"));
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
      psbt.signInput(
        i.index,
        ECPair.fromPrivateKey(account.privateKey!, {
          network: networks.bitcoin,
        }),
        i.sighashTypes
      );
    });
    psbt.finalizeAllInputs();
  }

  signMessage(address: Hex, text: string) {
    const account = this.findAccount(address);
    return account.sign(Buffer.from(text)).toString("base64");
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
      const child = (this.root as any)?.deriveChild(i);
      const ecpair = ECPair.fromPrivateKey(
        Buffer.from((child as any).privateKey)
      );
      this.accounts.push(ecpair);
    }

    return this.accounts[i];
  }
}

export default HDPrivateKey;

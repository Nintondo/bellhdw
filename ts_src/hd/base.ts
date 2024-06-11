import { Network, networks, payments } from "belcoinjs-lib";
import { AddressType } from "./types";

export class BaseWallet {
  addressType?: AddressType;
  network?: Network;

  getAddress(publicKey: Uint8Array) {
    if (this.addressType === undefined)
      throw new Error("addressType of keyring is not specified");
    switch (this.addressType) {
      case AddressType.P2WPKH:
        return payments.p2wpkh({
          pubkey: Buffer.from(publicKey),
          network: this.network ?? networks.bellcoin,
        }).address;
      case AddressType.P2SH_P2WPKH:
        return payments.p2sh({
          redeem: payments.p2wpkh({
            pubkey: Buffer.from(publicKey),
            network: this.network ?? networks.bellcoin,
          }),
        }).address;
      case AddressType.P2PKH as any:
        return payments.p2pkh({
          pubkey: Buffer.from(publicKey),
          network: this.network ?? networks.bellcoin,
        }).address;
      default:
        throw new Error("Invalid AddressType");
    }
  }
}

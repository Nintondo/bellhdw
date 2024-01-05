import HDPrivateKey from "./private";
import SimpleKey from "./simple";
import { AddressType, Keyring } from "./types";

export async function fromMnemonic(
  mnemonic: string,
  hideRoot?: boolean
): Promise<HDPrivateKey> {
  return await HDPrivateKey.fromMnemonic({ mnemonic, hideRoot });
}

export function fromPrivateKey(privateKey: Uint8Array): SimpleKey {
  return new SimpleKey(privateKey);
}

export { HDPrivateKey, SimpleKey };
export * as types from "./types";
export { default as englishWords } from "./words/english";
export { AddressType, Keyring };

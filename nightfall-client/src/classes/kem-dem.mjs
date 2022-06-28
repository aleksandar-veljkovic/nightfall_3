import { scalarMult } from 'common-files/utils/curve-maths/curves.mjs';
import config from 'config';
import mimcHash from 'common-files/utils/crypto/mimc/mimc.mjs';
import rand from 'common-files/utils/crypto/crypto-random.mjs';
import { generalise, stitchLimbs } from 'general-number';

const { BABYJUBJUB, BN128_GROUP_ORDER, ZKP_KEY_LENGTH } = config;
const DOMAIN_KEM = 21033365405711675223813179268586447041622169155539365736392974498519442361181n;
const DOMAIN_DEM = 1241463701002173366467794894814691939898321302682516549591039420117995599097n;

/**
This function is like splice but replaces the element in index and returns a new array
@function immutableSplice
@param {Array} array - The list that will be spliced into
@param {number} index - The index to be spliced into
@param {any} element - The element to be placed in index
@returns {Array} An updated array with element spliced in at index.
*/
const immutableSplice = (array, index, element) => {
  const safeIndex = Math.max(index, 0);
  const beforeElement = array.slice(0, safeIndex);
  const afterElement = array.slice(safeIndex + 1);
  return [...beforeElement, element, ...afterElement];
};

/**
This helper function finds the first element of the array that is !== '0'
@function findFirstByteIndex
@param {Array<string>} byteArray - An array of strings
@returns {number} The index of the first element !== '0'
*/
const findFirstByteIndex = byteArray => {
  for (let i = 0; i < byteArray.length; i++) {
    if (byteArray[i] !== '0') return i;
  }
  return byteArray.length - 1;
};

/**
This helper function moves the top most 32-bits from one general number to another
@function packSecrets
@param {GeneralNumber} from - The general number which the top more 32-bits will be taken from
@param {GeneralNumber} to - The general number which the top more 32-bits will be inserted into
@param {number} fromIndex - Used override the topmost 32-bits, move custom bit positions
@param {number} toIndex - Used override the topmost 32-bits, move custom bit positions
@returns {Array<GeneralNumber>} The two general numbers after moving the 32-bits.
*/
const packSecrets = (from, to, fromIndex = -1, toIndex = -1) => {
  // This moves the top most 32-bits from from to 'to'
  let topMostFromBytesIndex = fromIndex;
  let topMostToBytesIndex = toIndex;
  const fromLimbs = from.limbs(32, 8);
  const toLimbs = to.limbs(32, 8);
  if (toLimbs[0] !== '0') throw new Error('Cannot pack since top bits non-zero');
  if (topMostFromBytesIndex < 0) topMostFromBytesIndex = findFirstByteIndex(fromLimbs);
  if (topMostToBytesIndex < 0) topMostToBytesIndex = findFirstByteIndex(toLimbs);

  if (topMostToBytesIndex === toLimbs.length) throw new Error('Pack To Array is zero');
  const topMostBytes = fromLimbs[topMostFromBytesIndex];

  const unpackedFrom = immutableSplice(fromLimbs, topMostFromBytesIndex - 1, '0');
  const packedTo = immutableSplice(toLimbs, topMostToBytesIndex - 1, topMostBytes);
  return [generalise(stitchLimbs(unpackedFrom, 32)), generalise(stitchLimbs(packedTo, 32))];
};

/**
This function generates the ephemeral key pair used in the kem-dem
@function genEphemeralKeys
@returns {Promise<Array<GeneralNumber, Array<BigInt>>>} The private and public key pair
*/
const genEphemeralKeys = async () => {
  const privateKey = await rand(ZKP_KEY_LENGTH);
  const publicKey = scalarMult(privateKey.bigInt, BABYJUBJUB.GENERATOR);
  return [privateKey, publicKey];
};

/**
This function performs the key encapsulation step, deriving a symmetric encryption key from a shared secret.
@function kem
@param {GeneralNumber} privateKey - The private key related to either the ephemeralPub or recipientPubKey (depending on operation)
@param {Array<GeneralNumber>} ephemeralPub - The general number which the top more 32-bits will be inserted into
@param {Array<GeneralNumber>} recipientPubKey - The recipientPkd, in decryption this is also the ephemeralPub
@returns {Array<Array<GeneralNumber>, BigInt>>} The ephemeralPub key and the symmteric key used for encryption
*/
const kem = (privateKey, ephemeralPub, recipientPubKey) => {
  const sharedSecret = scalarMult(
    privateKey.bigInt,
    recipientPubKey.map(r => r.bigInt),
  );
  const encryptionKey = mimcHash([
    DOMAIN_KEM,
    sharedSecret[0],
    sharedSecret[1],
    ephemeralPub[0].bigInt,
    ephemeralPub[1].bigInt,
  ]);
  return [ephemeralPub, encryptionKey];
};

/**
This function performs the data encapsulation step, encrypting the plaintext
@function dem
@param {BigInt} encryptionKey - The symmetric encryption key
@param {Array<BigInt>} plaintexts - The array of plain text to be encrypted
@returns {Array<BigInt>} The encrypted ciphertexts.
*/
const dem = (encryptionKey, plaintexts) =>
  plaintexts.map(
    (p, i) => (BigInt(mimcHash([DOMAIN_DEM, encryptionKey, BigInt(i)])) + p) % BN128_GROUP_ORDER,
  );

/**
This function inverts the data encapsulation step, decrypting the ciphertext
@function deDem
@param {BigInt} encryptionKey - The symmetric encryption key
@param {Array<BigInt>} ciphertexts - The array of ciphertexts to be decrypted
@returns {Array<BigInt>} The decrypted plaintexts.
*/
const deDem = (encryptionKey, ciphertexts) => {
  const plainTexts = ciphertexts.map((c, i) => {
    const pt = c.bigInt - BigInt(mimcHash([DOMAIN_DEM, encryptionKey, BigInt(i)]));
    if (pt < 0) return ((pt % BN128_GROUP_ORDER) + BN128_GROUP_ORDER) % BN128_GROUP_ORDER;
    return pt % BN128_GROUP_ORDER;
  });
  return plainTexts;
};

/**
This function performs the kem-dem required to encrypt plaintext.
@function encrypt
@param {GeneralNumber} ephemeralPrivate - The private key that generates the ephemeralPub
@param {Array<GeneralNumber>} ephemeralPub - The ephemeralPubKey
@param {Array<GeneralNumber>} recipientPkds - The public pkd of the recipients
@param {Array<BigInt>} plaintexts - The array of plain text to be encrypted, the ordering is [ercAddress,tokenId, value, salt]
@returns {Array<BigInt>} The encrypted ciphertexts.
*/
const encrypt = (ephemeralPrivate, ephemeralPub, recipientPkds, plaintexts) => {
  const [, encKey] = kem(ephemeralPrivate, ephemeralPub, recipientPkds);
  return dem(encKey, plaintexts);
  // return cipherTexts;
};

/**
This function performs the kem-deDem required to decrypt plaintext.
@function decrypt
@param {GeneralNumber} privateKey - The private key of the recipient pkd
@param {Array<GeneralNumber>} ephemeralPub - The ephemeralPubKey
@param {Array<BigInt>} ciphertexts - The array of ciphertexts to be decrypted
@returns {Array<BigInt>} The decrypted plaintexts, the ordering is [ercAddress,tokenId, value, salt]
*/
const decrypt = (privateKey, ephemeralPub, cipherTexts) => {
  const [, encKey] = kem(privateKey, ephemeralPub, ephemeralPub);
  return deDem(encKey, cipherTexts);
};

export { encrypt, decrypt, kem, genEphemeralKeys, packSecrets };

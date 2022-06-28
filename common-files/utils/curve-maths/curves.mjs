/* ignore unused exports */

/**
module for manupulating elliptic curve points for an alt-bn128 curve. This
is the curve that Ethereum currently has pairing precompiles for. All the
return values are BigInts (or arrays of BigInts).
*/
// eslint-disable-next-line import/no-extraneous-dependencies
import config from 'config';
import { mulMod, addMod, squareRootModPrime } from '../crypto/number-theory.mjs';
import Fq2 from '../../classes/fq2.mjs';
import Proof from '../../classes/proof.mjs';
import { modDivide } from '../crypto/modular-division.mjs';

const { BN128_PRIME_FIELD, BN128_GROUP_ORDER, BABYJUBJUB } = config;

const one = BigInt(1);
const { JUBJUBE, JUBJUBC } = BABYJUBJUB;
const Fp = BN128_GROUP_ORDER; // the prime field used with the curve E(Fp)
const Fq = JUBJUBE / JUBJUBC;

/**
function to compress a G1 point. If we throw away the y coodinate, we can
recover it using the curve equation later, and save almost half the storage.
Unfortunately that gives us a choice of two y points because of the
quadratic term in y.  We have two solutions. We could save the sign of y or,
in a prime field, we can save the parity of y: if y is even, -y (=p-y) must
be odd and vice versa. We do the latter because it's slightly easier to
extract.
*/
export function compressG1(point) {
  const [x, y] = point.map(p => BigInt(p));
  // compute whether y is odd or even
  const parity = y.toString(2).slice(-1); // extract last binary digit
  // add the parity bit to the x cordinate (x,y are 254 bits long - the final
  // string is 256 bits to fit with an Ethereum word)
  const compressedBinary = parity.concat(x.toString(2).padStart(255, '0'));
  const compressedBigInt = BigInt(`0b${compressedBinary}`);
  return `0x${compressedBigInt.toString(16)}`;
}

/**
The G2 point works over the complex extension field F_p^2 = F_p[i] / (i^2 + 1) so here x,y are complex! Thus the point is of the form [[xr, xi],[yr, yi]]
*/
export function compressG2(point) {
  const [[xr, xi], [yr, yi]] = point.map(c => c.map(p => BigInt(p)));
  return [compressG1([xr, yr]), compressG1([xi, yi])];
}

/**
This compresses a GM17 proof object in its entirety, returning promises of a
flattened, compressed result. That's nice because you can await it with a
Promise.all. We can turn off G2 compression as G2 decompression isn't done yet.
It can cope with the proof as an object or as a flattened array.
*/
export function compressProof(_proof) {
  let proof;
  if (Array.isArray(_proof)) {
    if (_proof.length !== 8) throw new Error('Flat proof array should have length 8');
    proof = new Proof(_proof);
  } else proof = _proof;
  const compressed = [compressG1(proof.a), compressG2(proof.b), compressG1(proof.c)];
  return compressed.flat();
}

/**
solving Y^2 = X^3 + 3 over p
*/
export function decompressG1(xin) {
  // first, extract the parity bit
  const xbin = BigInt(xin).toString(2).padStart(256, '0');
  const parity = xbin[0];
  // then convert the rest into a BigInt
  const x = BigInt(`0b${xbin.slice(1)}`);
  const x3 = mulMod([x, x, x], BN128_PRIME_FIELD);
  const y2 = addMod([x3, 3n], BN128_PRIME_FIELD);
  let y = squareRootModPrime(y2, BN128_PRIME_FIELD);
  if (parity !== y.toString(2).slice(-1)) y = BN128_PRIME_FIELD - y;
  return [`0x${x.toString(16).padStart(64, '0')}`, `0x${y.toString(16).padStart(64, '0')}`];
}

/**
solving Y^2 = X^3 + 3/(i+9)
*/
export function decompressG2(xin) {
  // first extract parity bits
  const xbin = xin.map(c => BigInt(c).toString(2).padStart(256, '0'));
  const parity = xbin.map(xb => xb[0]); // extract parity
  const x = new Fq2(...xbin.map(xb => BigInt(`0b${xb.slice(1)}`))); // x element
  const x3 = x.mul(x).mul(x);
  const d = new Fq2(3n, 0n).div(new Fq2(9n, 1n)); // TODO hardcode this?
  const y2 = x3.add(d);
  const y = y2.sqrt();
  // fix the parity of y
  const a = parity[0] === y.real.toString(2).slice(-1) ? y.real : BN128_PRIME_FIELD - y.real;
  const b =
    parity[1] === y.imaginary.toString(2).slice(-1) ? y.imaginary : BN128_PRIME_FIELD - y.imaginary;
  // we return arrays of real and imaginary points not Fq2.
  return [x.toHex(), new Fq2(a, b).toHex()];
}

export function decompressProof(compressedProof) {
  // compressed proofs are always just flat arrays. We also return a flattend
  // proof array as we rarely need the object.  If we do we can construct one
  // from the flattened array as an instance of the Proof class. This returns
  // and array of promises so be sure to await Promise.all.
  const [aCompressed, bCompressedReal, bCompressedImaginary, cCompressed] = compressedProof;
  return [
    decompressG1(aCompressed),
    decompressG2([bCompressedReal, bCompressedImaginary]),
    decompressG1(cCompressed),
  ].flat(2);
}

function isOnCurve(p) {
  const { JUBJUBA: a, JUBJUBD: d } = BABYJUBJUB;
  const uu = (p[0] * p[0]) % Fp;
  const vv = (p[1] * p[1]) % Fp;
  const uuvv = (uu * vv) % Fp;
  return (a * uu + vv) % Fp === (one + d * uuvv) % Fp;
}

/**
Point addition on the babyjubjub curve TODO - MOD P THIS
*/
export function add(p, q) {
  const { JUBJUBA: a, JUBJUBD: d } = BABYJUBJUB;
  const u1 = p[0];
  const v1 = p[1];
  const u2 = q[0];
  const v2 = q[1];
  const uOut = modDivide(u1 * v2 + v1 * u2, one + d * u1 * u2 * v1 * v2, Fp);
  const vOut = modDivide(v1 * v2 - a * u1 * u2, one - d * u1 * u2 * v1 * v2, Fp);
  if (!isOnCurve([uOut, vOut])) throw new Error('Addition point is not on the babyjubjub curve');
  return [uOut, vOut];
}

/**
Scalar multiplication on a babyjubjub curve
@param {String} scalar - scalar mod q (will wrap if greater than mod q, which is probably ok)
@param {Object} h - curve point in u,v coordinates
*/
export function scalarMult(scalar, h, form = 'Edwards') {
  const { INFINITY } = BABYJUBJUB;
  const a = ((BigInt(scalar) % Fq) + Fq) % Fq; // just in case we get a value that's too big or negative
  const exponent = a.toString(2).split(''); // extract individual binary elements
  let doubledP = [...h]; // shallow copy h to prevent h being mutated by the algorithm
  let accumulatedP = INFINITY;
  for (let i = exponent.length - 1; i >= 0; i--) {
    const candidateP = add(accumulatedP, doubledP, form);
    accumulatedP = exponent[i] === '1' ? candidateP : accumulatedP;
    doubledP = add(doubledP, doubledP, form);
  }
  if (!isOnCurve(accumulatedP))
    throw new Error('Scalar multiplication point is not on the babyjubjub curve');
  return accumulatedP;
}

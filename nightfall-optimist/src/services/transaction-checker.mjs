/**
Module to check that a transaction is valid before it goes into a Block.
Here are the things that could be wrong with a transaction:
- the proof doesn't verify
- the transaction hash doesn't match with the preimage
- the transaction type is inconsistent with the fields populated
- the public inputs hash is correct
*/
import config from 'config';
import axios from 'axios';
import logger from 'common-files/utils/logger.mjs';
import {
  Transaction,
  VerificationKey,
  Proof,
  TransactionError,
  PublicInputs,
} from '../classes/index.mjs';
import { waitForContract } from '../event-handlers/subscribe.mjs';
import { getBlockByBlockNumberL2 } from './database.mjs';

const { ZOKRATES_WORKER_HOST, PROVING_SCHEME, BACKEND, CURVE, ZERO, CHALLENGES_CONTRACT_NAME } =
  config;

// first, let's check the hash. That's nice and easy:
// NB as we actually now comput the hash on receipt of the transaction this
// _should_ never fail.  Consider removal in the future.
async function checkTransactionHash(transaction) {
  if (!Transaction.checkHash(transaction)) {
    logger.debug(
      `The transaction with the hash that didn't match was ${JSON.stringify(transaction, null, 2)}`,
    );
    throw new TransactionError('The transaction hash did not match the transaction data', 0);
  }
}
// next that the fields provided are consistent with the transaction type
async function checkTransactionType(transaction) {
  logger.debug(`in checkTransactionType: ${JSON.stringify(transaction)}`);
  switch (Number(transaction.transactionType)) {
    // Assuming nullifiers and commitments can't be valid ZEROs.
    // But points can such as compressedSecrets, Proofs
    case 0: // deposit
      if (
        transaction.publicInputHash === ZERO ||
        (Number(transaction.tokenType) !== 0 &&
          transaction.tokenId === ZERO &&
          Number(transaction.value) === 0) ||
        transaction.ercAddress === ZERO ||
        transaction.recipientAddress !== ZERO ||
        transaction.commitments[0] === ZERO ||
        transaction.commitments[1] !== ZERO ||
        transaction.commitments.length !== 2 ||
        transaction.nullifiers.some(n => n !== ZERO) ||
        transaction.compressedSecrets.some(cs => cs !== ZERO) ||
        transaction.compressedSecrets.length !== 8 ||
        transaction.proof.every(p => p === ZERO) ||
        // This extra check is unique to deposits
        Number(transaction.historicRootBlockNumberL2) !== 0
      )
        throw new TransactionError(
          'The data provided was inconsistent with a transaction type of DEPOSIT',
          1,
        );
      break;
    case 1: // single token transaction
      if (
        transaction.publicInputHash === ZERO ||
        transaction.tokenId !== ZERO ||
        Number(transaction.value) !== 0 ||
        transaction.ercAddress === ZERO ||
        transaction.recipientAddress !== ZERO ||
        transaction.commitments[0] === ZERO ||
        transaction.commitments[1] !== ZERO ||
        transaction.commitments.length !== 2 ||
        transaction.nullifiers[0] === ZERO ||
        transaction.nullifiers[1] !== ZERO ||
        transaction.nullifiers.length !== 2 ||
        transaction.compressedSecrets.every(cs => cs === ZERO) ||
        transaction.compressedSecrets.length !== 8 ||
        transaction.proof.every(p => p === ZERO)
      )
        throw new TransactionError(
          'The data provided was inconsistent with a transaction type of SINGLE_TRANSFER',
          1,
        );
      break;
    case 2: // double token transaction
      if (
        transaction.publicInputHash === ZERO ||
        transaction.tokenId !== ZERO ||
        Number(transaction.value) !== 0 ||
        transaction.ercAddress === ZERO ||
        transaction.recipientAddress !== ZERO ||
        transaction.commitments.some(c => c === ZERO) ||
        transaction.commitments.length !== 2 ||
        transaction.nullifiers.some(n => n === ZERO) ||
        transaction.nullifiers.length !== 2 ||
        transaction.compressedSecrets.every(cs => cs === ZERO) ||
        transaction.compressedSecrets.length !== 8 ||
        transaction.proof.every(p => p === ZERO)
      )
        throw new TransactionError(
          'The data provided was inconsistent with a transaction type of DOUBLE_TRANSFER',
          1,
        );
      break;
    case 3: // withdraw transaction
      if (
        transaction.publicInputHash === ZERO ||
        (Number(transaction.tokenType) !== 0 &&
          transaction.tokenId === ZERO &&
          Number(transaction.value) === 0) ||
        transaction.ercAddress === ZERO ||
        transaction.recipientAddress === ZERO ||
        transaction.commitments.some(c => c !== ZERO) ||
        transaction.nullifiers[0] === ZERO ||
        transaction.nullifiers[1] !== ZERO ||
        transaction.nullifiers.length !== 2 ||
        transaction.compressedSecrets.some(cs => cs !== ZERO) ||
        transaction.proof.every(p => p === ZERO)
      )
        throw new TransactionError(
          'The data provided was inconsistent with a transaction type of WITHDRAW',
          1,
        );
      break;
    default:
      throw new TransactionError('Unknown transaction type', 2);
  }
}

async function checkHistoricRoot(transaction) {
  // Deposit transaction have a historic root of 0
  // the validity is tested in checkTransactionType
  if (
    Number(transaction.transactionType) === 1 ||
    Number(transaction.transactionType) === 2 ||
    Number(transaction.transactionType) === 3
  ) {
    if ((await getBlockByBlockNumberL2(transaction.historicRootBlockNumberL2)) === null)
      throw new TransactionError('The historic root in the transaction does not exist', 3);
  }
}

async function checkPublicInputHash(transaction) {
  try {
    // We will check if the historic root used in transaction exists first because this check is done by
    // looking up for a block with block number in the database. This same look up needs to be done during public input hash
    // to retrieve the root of the block that needs to be hashed. If the historic block does not exist then this root won't exist either
    // hence we do this check first
    await checkHistoricRoot(transaction);
    switch (Number(transaction.transactionType)) {
      case 0: // deposit transaction
        if (
          transaction.publicInputHash !==
          new PublicInputs([
            transaction.ercAddress,
            transaction.tokenId,
            transaction.value,
            transaction.commitments[0],
          ]).hash.hex(32)
        )
          throw new TransactionError('public input hash is incorrect', 4);
        break;
      case 1: // single transfer transaction
        if (
          transaction.publicInputHash !==
          new PublicInputs([
            transaction.ercAddress,
            transaction.commitments[0],
            transaction.nullifiers[0],
            (await getBlockByBlockNumberL2(transaction.historicRootBlockNumberL2)).root,
            ...transaction.compressedSecrets,
          ]).hash.hex(32)
        )
          throw new TransactionError('public input hash is incorrect', 4);
        break;
      case 2: // double transfer transaction
        if (
          transaction.publicInputHash !==
          new PublicInputs([
            transaction.ercAddress, // this is correct; ercAddress appears twice
            transaction.ercAddress, // in a double-transfer public input hash
            transaction.commitments,
            transaction.nullifiers,
            (await getBlockByBlockNumberL2(transaction.historicRootBlockNumberL2)).root,
            ...transaction.compressedSecrets,
          ]).hash.hex(32)
        )
          throw new TransactionError('public input hash is incorrect', 4);
        break;
      case 3: // withdraw transaction
        if (
          transaction.publicInputHash !==
          new PublicInputs([
            transaction.ercAddress,
            transaction.tokenId,
            transaction.value,
            transaction.nullifiers[0],
            transaction.recipientAddress,
            (await getBlockByBlockNumberL2(transaction.historicRootBlockNumberL2)).root,
          ]).hash.hex(32)
        )
          throw new TransactionError('public input hash is incorrect', 4);
        break;
      default:
        throw new TransactionError('Unknown transaction type', 2);
    }
  } catch (err) {
    throw new TransactionError(err.message, err.code);
  }
}

async function verifyProof(transaction) {
  // we'll need the verification key.  That's actually stored in the b/c
  const challengeInstance = await waitForContract(CHALLENGES_CONTRACT_NAME);
  const vkArray = await challengeInstance.methods
    .getVerificationKey(transaction.transactionType)
    .call();
  // to verify a proof, we make use of a zokrates-worker, which has an offchain
  // verifier capability
  const res = await axios.post(`http://${ZOKRATES_WORKER_HOST}/verify`, {
    vk: new VerificationKey(vkArray),
    proof: new Proof(transaction.proof),
    provingScheme: PROVING_SCHEME,
    backend: BACKEND,
    curve: CURVE,
    inputs: [transaction.publicInputHash],
  });
  const { verifies } = res.data;
  if (!verifies) throw new TransactionError('The proof did not verify', 5);
}

function checkTransaction(transaction) {
  return Promise.all([
    checkTransactionHash(transaction),
    checkTransactionType(transaction),
    checkPublicInputHash(transaction),
    verifyProof(transaction),
  ]);
}

export default checkTransaction;

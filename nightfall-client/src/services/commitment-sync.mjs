/**
commitmentsync services to decrypt commitments from transaction blockproposed events 
or use clientCommitmentSync to decrypt when new ivk is received.
*/

import config from 'config';
import logger from 'common-files/utils/logger.mjs';
import { generalise } from 'general-number';
import { edwardsDecompress } from 'common-files/utils/curve-maths/curves.mjs';
import { getAllTransactions } from './database.mjs';
import { countCommitments, storeCommitment } from './commitment-storage.mjs';
import { decrypt, packSecrets } from './kem-dem.mjs';
import { calculatePkd } from './keys.mjs';
import Commitment from '../classes/commitment.mjs';

const { ZERO } = config;

/**
decrypt commitments for a transaction given ivks and nsks.
*/
export async function decryptCommitment(transaction, ivk, nsk) {
  const nonZeroCommitments = transaction.commitments.flat().filter(n => n !== ZERO);
  const storeCommitments = [];
  ivk.forEach((key, j) => {
    const { pkd, compressedPkd } = calculatePkd(generalise(key));
    try {
      const cipherTexts = [
        transaction.ercAddress,
        transaction.tokenId,
        ...transaction.compressedSecrets,
      ];
      const [packedErc, unpackedTokenID, ...rest] = decrypt(
        generalise(key),
        generalise(edwardsDecompress(transaction.recipientAddress)),
        generalise(cipherTexts),
      );
      const [erc, tokenId] = packSecrets(generalise(packedErc), generalise(unpackedTokenID), 2, 0);
      const plainTexts = generalise([erc, tokenId, ...rest]);
      const commitment = new Commitment({
        compressedPkd,
        pkd,
        ercAddress: plainTexts[0].bigInt,
        tokenId: plainTexts[1].bigInt,
        value: plainTexts[2].bigInt,
        salt: plainTexts[3].bigInt,
      });
      if (commitment.hash.hex(32) === nonZeroCommitments[0]) {
        storeCommitments.push(storeCommitment(commitment, nsk[j]));
      } else {
        logger.info("This encrypted message isn't for this recipient");
      }
    } catch (err) {
      logger.info(err);
      logger.info("This encrypted message isn't for this recipient");
    }
  });
  await Promise.all(storeCommitments).catch(function (err) {
    logger.info(err);
  });
}

/**
Called when new ivk(s) are recieved , it fetches all available commitments 
from commitments collection and decrypts commitments belonging to the new ivk(s).
*/
export async function clientCommitmentSync(ivk, nsk) {
  const transactions = await getAllTransactions();
  for (let i = 0; i < transactions.length; i++) {
    // filter out non zero commitments and nullifiers
    const nonZeroCommitments = transactions[i].commitments.flat().filter(n => n !== ZERO);
    if (
      (transactions[i].transactionType === '1' || transactions[i].transactionType === '2') &&
      countCommitments(nonZeroCommitments) === 0
    )
      decryptCommitment(transactions[i], ivk, nsk);
  }
}

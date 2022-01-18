/* ignore unused exports */
/**
 * This module enables setting instant withdrawals fees
 */

// eslint-disable-next-line import/no-extraneous-dependencies
import config from 'config';
import { getContractInstance } from '../../common-files/utils/contract';
import { Transaction } from '../classes/index';
import { buildSolidityStruct } from './finalise-withdrawal';
import { getTransactionByTransactionHash, getBlockByTransactionHash } from './database';

const { SHIELD_CONTRACT_NAME } = config;

const setInstantWithdrawl = async ({ transactionHash }) => {
  const block = await getBlockByTransactionHash(transactionHash);
  const transactions = await Promise.all(
    block.transactionHashes.map(t => getTransactionByTransactionHash(t)),
  );
  const index = transactions.findIndex(f => f.transactionHash === transactionHash);
  const shieldContractInstance = await getContractInstance(SHIELD_CONTRACT_NAME);
  try {
    const rawTransaction = await shieldContractInstance.methods
      .setAdvanceWithdrawalFee(
        buildSolidityStruct(block),
        block.blockNumberL2,
        transactions.map(t => Transaction.buildSolidityStruct(t)),
        index,
      )
      .encodeABI();
    return { rawTransaction };
  } catch (error) {
    throw new Error(error);
  }
};
export default setInstantWithdrawl;
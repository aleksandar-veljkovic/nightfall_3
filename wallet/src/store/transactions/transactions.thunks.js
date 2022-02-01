/* ignore unused exports */
import * as Nf3 from 'nf3';
import {
  TRANSACTION_RETRY_PERIOD,
  TRANSACTION_MAX_RETRIES,
  ERROR_AUTO_HIDE_PERIOD,
} from '../../constants';
import toBaseUnit from '../../utils/lib/utils';
import * as txActions from './transactions.actions';
import * as messageActions from '../message/message.actions';
import deposit from '../../nightfall-browser/services/deposit';
import transfer from '../../nightfall-browser/services/transfer';
import withdraw from '../../nightfall-browser/services/withdraw';
import { approve, submitTransaction } from '../../common-files/utils/contract';

function txInstantWithdrawSubmit(withdrawTransactionHash, fee) {
  return async (dispatch, getState) => {
    const {
      login: { nf3 },
      transactions: { txPool },
    } = getState();
    nf3
      .requestInstantWithdrawal(withdrawTransactionHash, fee)
      .then(txReceipt => {
        if (txReceipt === null) {
          throw new Error('Non existent hash');
        }
        // TODO dispatch error
        dispatch(txActions.txSuccess(Nf3.Constants.TX_TYPES.INSTANT_WITHDRAW, txReceipt));
        dispatch(messageActions.newInfo('Instant Withdrawal submitted'));
        setTimeout(() => {
          dispatch(messageActions.clearMsg());
        }, ERROR_AUTO_HIDE_PERIOD);
      })
      .catch(err => {
        // TODO: Wait XXX time and retry YYY times. Else fail
        const withdrawTx = txPool.filter(
          tx => tx.withdrawTransactionHash === withdrawTransactionHash,
        )[0];
        if (withdrawTx.nRetries < TRANSACTION_MAX_RETRIES) {
          // update retries of this tx
          dispatch(txActions.txRetry(withdrawTransactionHash));
          setTimeout(() => {
            dispatch(txInstantWithdrawSubmit(withdrawTransactionHash, fee));
          }, TRANSACTION_RETRY_PERIOD);
        } else {
          dispatch(txActions.txFailed());
        }
        // TODO dispatch error
        console.log(err);
      });
  };
}

function txSubmit(txParams) {
  const tokenAmountWei = toBaseUnit(txParams.tokenAmount).toString();
  // TODO: offchain needs to be a value from form
  const offchain = false;

  return async (dispatch, getState) => {
    const {
      login: { nf3 },
    } = getState();

    dispatch(txActions.txDispatch());
    switch (txParams.txType) {
      case Nf3.Constants.TX_TYPES.DEPOSIT:
        approve(
          txParams.tokenAddress,
          nf3.shieldContractAddress,
          txParams.tokenType,
          tokenAmountWei,
        )
          .then(() => {
            return deposit(
              {
                ercAddress: txParams.tokenAddress,
                tokenId: txParams.tokenId,
                value: tokenAmountWei,
                pkd: nf3.zkpKeys.pkd,
                nsk: nf3.zkpKeys.nsk,
                fee: txParams.fee,
                tokenType: txParams.tokenType,
              },
              nf3.shieldContractAddress,
            );
          })
          .then(async ({ rawTransaction }) => {
            return submitTransaction(rawTransaction, nf3.shieldContractAddress, txParams.fee);
            // dispatch(txActions.txSuccess(Nf3.Constants.TX_TYPES.DEPOSIT, txReceipt));
            // TODO: dispatch error
          })
          .then(txReceipt => {
            dispatch(txActions.txSuccess(Nf3.Constants.TX_TYPES.DEPOSIT, txReceipt));
            dispatch(messageActions.newInfo('Deposit submitted'));
            setTimeout(() => {
              dispatch(messageActions.clearMsg());
            }, ERROR_AUTO_HIDE_PERIOD);
            // TODO: dispatch error
          })
          .catch(err => {
            dispatch(txActions.txFailed());
            dispatch(messageActions.newError('Deposit Failed'));
            setTimeout(() => {
              dispatch(messageActions.clearMsg());
            }, ERROR_AUTO_HIDE_PERIOD);
            // TODO: dispatch error
            console.log(err);
          });
        break;

      case Nf3.Constants.TX_TYPES.TRANSFER:
        // TODO: dispatch error
        // { ercAddress, tokenId, recipientData, nsk, ask, fee }
        // { recipientCompressedPkds, values }
        transfer(
          {
            offchain,
            ercAddress: txParams.tokenAddress,
            tokenId: txParams.tokenId,
            recipientData: {
              recipientCompressedPkds: [txParams.compressedPkd],
              values: [tokenAmountWei],
            },
            nsk: nf3.zkpKeys.nsk,
            ask: nf3.zkpKeys.ask,
            fee: txParams.fee,
          },
          nf3.shieldContractAddress,
        )
          .then(async ({ rawTransaction }) => {
            console.log('rawTransaction', rawTransaction);
            return nf3.submitTransaction(rawTransaction, nf3.shieldContractAddress, txParams.fee);
            // dispatch(txActions.txSuccess(Nf3.Constants.TX_TYPES.DEPOSIT, txReceipt));
            // TODO: dispatch error
          })
          .then(txReceipt => {
            dispatch(txActions.txSuccess(Nf3.Constants.TX_TYPES.TRANSFER, txReceipt));
            dispatch(messageActions.newInfo('Transfer submitted'));
            setTimeout(() => {
              dispatch(messageActions.clearMsg());
            }, ERROR_AUTO_HIDE_PERIOD);
            // TODO: dispatch error
            console.log(txReceipt);
          })
          .catch(err => {
            dispatch(txActions.txFailed());
            dispatch(messageActions.newError('Transfer Failed'));
            setTimeout(() => {
              dispatch(messageActions.clearMsg());
            }, ERROR_AUTO_HIDE_PERIOD);
            // TODO: dispatch error
            console.log(err);
            console.log('SFSDFSDFD');
          });
        break;

      case Nf3.Constants.TX_TYPES.WITHDRAW:
      case Nf3.Constants.TX_TYPES.INSTANT_WITHDRAW:
        {
          // TODO: dispatch error
          const nRetries = 0;
          // { ercAddress, tokenId, value, recipientAddress, nsk, ask, fee, tokenType }
          withdraw(
            {
              ercAddress: txParams.tokenAddress,
              tokenId: txParams.tokenId,
              value: tokenAmountWei,
              recipientAddress: txParams.ethereumAddress,
              nsk: nf3.zkpKeys.nsk,
              ask: nf3.zkpKeys.ask,
              tokenType: txParams.tokenType,
              fees: txParams.fee,
            },
            nf3.shieldContractAddress,
          )
            .then(async ({ rawTransaction }) => {
              console.log('rawTransaction', rawTransaction);
              return nf3.submitTransaction(rawTransaction, nf3.shieldContractAddress, txParams.fee);
              // dispatch(txActions.txSuccess(Nf3.Constants.TX_TYPES.DEPOSIT, txReceipt));
              // TODO: dispatch error
            })
            .then(txReceipt => {
              const latestWithdrawTransactionHash = nf3.getLatestWithdrawHash();
              dispatch(
                txActions.txSuccess(
                  Nf3.Constants.TX_TYPES.WITHDRAW,
                  txReceipt,
                  latestWithdrawTransactionHash,
                  nRetries,
                ),
              );
              dispatch(messageActions.newInfo('Withdrawal submitted'));
              setTimeout(() => {
                dispatch(messageActions.clearMsg());
              }, ERROR_AUTO_HIDE_PERIOD);
              // TODO: dispatch error
              console.log(txReceipt);

              if (txParams.txType === Nf3.Constants.TX_TYPES.INSTANT_WITHDRAW) {
                dispatch(
                  txInstantWithdrawSubmit(
                    latestWithdrawTransactionHash,
                    txParams.instantWithdrawFee,
                  ),
                );
              }
            })
            .catch(err => {
              dispatch(txActions.txFailed());
              dispatch(messageActions.newError('Withdraw Failed'));
              setTimeout(() => {
                dispatch(messageActions.clearMsg());
              }, ERROR_AUTO_HIDE_PERIOD);
              // TODO: dispatch error
              console.log(err);
            });
        }
        break;

      default:
        throw new Error('Unknown transaction', txParams.txType);
    }
  };
}

export { txSubmit, txInstantWithdrawSubmit };

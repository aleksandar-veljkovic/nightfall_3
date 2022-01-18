/**
 Route for commitment to access commitment data from the database
 */

import express from 'express';
import logger from 'common-files/utils/logger.mjs';
import {
  getCommitmentBySalt,
  getWalletBalance,
  getWalletCommitments,
  getWithdrawCommitments,
  getWalletBalanceDetails,
  getWalletPendingDepositBalance,
  getWalletPendingSpentBalance,
} from '../services/commitment-storage.mjs';

const router = express.Router();

router.get('/salt', async (req, res, next) => {
  logger.debug('commitment/salt endpoint received GET');
  try {
    const { salt } = req.query;
    const commitment = await getCommitmentBySalt(salt);
    if (commitment === null) logger.debug(`Found commitment ${commitment} for salt ${salt}`);
    else logger.debug(`No commitment found for salt ${salt}`);
    res.json({ commitment });
  } catch (err) {
    logger.error(err);
    next(err);
  }
});

router.post('/balance', async (req, res, next) => {
  logger.debug('commitment/balance endpoint received GET');
  try {
    const { compressedPkd, ercList } = req.body;
    logger.debug(`Details requested with compressedPkd ${compressedPkd} and ercList ${ercList}`);
    const balance = await getWalletBalance(compressedPkd, ercList);
    res.json({ balance });
  } catch (err) {
    logger.error(err);
    next(err);
  }
});

router.post('/balance-details', async (req, res, next) => {
  logger.debug('commitment/balance details endpoint received POST');
  try {
    const { compressedPkd, ercList } = req.body;
    const balance = await getWalletBalanceDetails(compressedPkd, ercList);
    res.json({ balance });
  } catch (err) {
    logger.error(err);
    next(err);
  }
});

router.post('/pending-deposit', async (req, res, next) => {
  logger.debug('commitment/pending-deposit endpoint received POST');
  try {
    const { compressedPkd, ercList } = req.body;
    logger.debug(`Details requested with compressedPkd ${compressedPkd} and ercList ${ercList}`);
    const balance = await getWalletPendingDepositBalance(compressedPkd, ercList);
    res.json({ balance });
  } catch (err) {
    logger.error(err);
    next(err);
  }
});

router.post('/pending-spent', async (req, res, next) => {
  logger.debug('commitment/pending-spent endpoint received POST');
  try {
    const { compressedPkd, ercList } = req.body;
    logger.debug(`Details requested with compressedPkd ${compressedPkd} and ercList ${ercList}`);
    const balance = await getWalletPendingSpentBalance(compressedPkd, ercList);
    res.json({ balance });
  } catch (err) {
    logger.error(err);
    next(err);
  }
});

router.get('/commitments', async (req, res, next) => {
  logger.debug('commitment/commitments endpoint received GET');
  try {
    const commitments = await getWalletCommitments();
    res.json({ commitments });
  } catch (err) {
    logger.error(err);
    next(err);
  }
});

router.get('/withdraws', async (req, res, next) => {
  logger.debug('commitment/withdraws endpoint received GET');
  try {
    const commitments = await getWithdrawCommitments();
    res.json({ commitments });
  } catch (err) {
    logger.error(err);
    next(err);
  }
});

export default router;

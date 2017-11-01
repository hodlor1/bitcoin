// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "arith_uint256.h"
#include "chain.h"
#include "primitives/block.h"
#include "uint256.h"
#include "streams.h"
#include "hash.h"
#include "version.h"
#include "crypto/cuckoo.h"

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    int currentBlockHeight = pindexLast->nHeight+1;
	const uint256 usedPowLimit = (currentBlockHeight >= params.CuckooHardForkBlockHeight)? params.cuckooPowLimit : params.powLimit;
	unsigned int nUsedPowLimit = UintToArith256(usedPowLimit).GetCompact();


    // Only change once per difficulty adjustment interval
    if (currentBlockHeight % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nUsedPowLimit;
	     else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nUsedPowLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }

		// Emergency retarget: If the last 6 blocks(without retargeting) took more than 1 hour each on average 
		// retarget halfway closer to last easier difficulty
		if (currentBlockHeight > params.CuckooHardForkBlockHeight && pindexLast->nBits != nUsedPowLimit)
		{
			const int blocksPast = 6;
			const CBlockIndex *pindexAnc = pindexLast->GetAncestor(currentBlockHeight - 1 - blocksPast);
			assert(pindexAnc);
			int64_t timePast = pindexLast->GetMedianTimePast() - pindexAnc->GetMedianTimePast();
			int64_t retargetLimit = params.nPowTargetSpacing * 6 * blocksPast;

			if (pindexLast->nBits == pindexAnc->nBits && timePast > retargetLimit)
			{
				const CBlockIndex* pindex = pindexAnc;
				arith_uint256 bnCurrent, bnPrev;
				bnCurrent.SetCompact(pindexLast->nBits);
				while (pindex && bnPrev.SetCompact(pindex->nBits) <= bnCurrent)
					pindex = pindex->pprev;

				assert(pindex);
				bnCurrent += bnPrev;
				bnCurrent /= 2;

				return bnCurrent.GetCompact();
			}
		}
		return pindexLast->nBits;
    } 
    else if (currentBlockHeight == params.CuckooHardForkBlockHeight)
	{
        return nUsedPowLimit;
    }

    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

	int currentBlockHeight = pindexLast->nHeight+1;
	const uint256 powLimit = (currentBlockHeight >= params.CuckooHardForkBlockHeight)? params.cuckooPowLimit : params.powLimit;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(powLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

bool CheckProofOfWork(const CBlockHeader& blockHeader, const Consensus::Params& params) {
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(blockHeader.nBits, &fNegative, &fOverflow);

    // Check range
	if (fNegative || bnTarget == 0 || fOverflow || bnTarget > (blockHeader.isCuckooPow() ? UintToArith256(params.cuckooPowLimit) : UintToArith256(params.powLimit)))
        return false;

    // If after cuckoo cycle pow change HF, verify the cuckoo cycle is valid
    if (blockHeader.isCuckooPow() && !CheckCuckooProofOfWork(blockHeader, params))
		return false;

    // Check block proof of work matches claimed amount
    if (UintToArith256(blockHeader.GetHash()) > bnTarget)
        return false;

    return true;
}

bool CheckCuckooProofOfWork(const CBlockHeader& blockHeader, const Consensus::Params& params) {
    // Serialize header and trim to 80 bytes
    std::vector<unsigned char> serializedHeader;
    CVectorWriter(SER_NETWORK, INIT_PROTO_VERSION, serializedHeader, 0, blockHeader);
    serializedHeader.resize(80);

    unsigned char hash[32];
    CSHA256().Write((const unsigned char *)serializedHeader.data(), 80).Finalize(hash);
	return CCuckooCycleVerfier::verify((unsigned int *)blockHeader.cuckooProof, hash, params.cuckooGraphSize -1) == cuckoo_cycle::POW_OK;
}

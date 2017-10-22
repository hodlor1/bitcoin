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
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();
    unsigned int nCuckooProofOfWorkLimit = UintToArith256(params.cuckooPowLimit).GetCompact();

    int currentBlockHeight = pindexLast->nHeight+1;

    // Only change once per difficulty adjustment interval
    if (currentBlockHeight % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return (currentBlockHeight >= params.CuckooHardForkBlockHeight)? nCuckooProofOfWorkLimit : nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    } 
    else if (currentBlockHeight == params.CuckooHardForkBlockHeight) {
        return nCuckooProofOfWorkLimit;
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

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
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
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    uint256 hash;

    // If after cuckoo cycle pow change HF, check cuckoo proof of work hash instead
    if ((blockHeader.nVersion & CUCKOO_HARDFORK_VERSION_MASK) == CUCKOO_HARDFORK_VERSION_MASK) {
        if (!CheckCuckooProofOfWork(blockHeader)) 
     	    return false;

        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        for (int i=0; i<42; i++) {
            ss << blockHeader.cuckooProof[i];
        }
        hash = ss.GetHash();
    } else {
        hash = blockHeader.GetHash();
    }


    // Check block proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}

bool CheckCuckooProofOfWork(const CBlockHeader& blockHeader) {
    // Serialize header and trim to 80 bytes
    std::vector<unsigned char> serializedHeader;
    CVectorWriter(SER_NETWORK, INIT_PROTO_VERSION, serializedHeader, 0, blockHeader);
    serializedHeader.resize(80);

    unsigned char hash[32];
    CSHA256().Write((const unsigned char *)serializedHeader.data(), 80).Finalize(hash);
    return CCuckooCycleVerfier::verify((unsigned int *)blockHeader.cuckooProof, hash, 29)  == cuckoo_cycle::POW_OK;
}

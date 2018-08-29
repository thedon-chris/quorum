package quorum

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"sync"
	"time"

	"gopkg.in/fatih/set.v0"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/logger"
	"github.com/ethereum/go-ethereum/logger/glog"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
)

const (
	// Create bindings with: go run cmd/abigen/main.go -abi <definition> -pkg quorum -type VotingContract > core/quorum/binding.go
	// TODO: Make new binding file
	// ABI = `[{"constant":false,"inputs":[{"name":"threshold","type":"uint256"}],"name":"setVoteThreshold","outputs":[],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"addr","type":"address"}],"name":"removeBlockMaker","outputs":[],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"voterCount","outputs":[{"name":"","type":"uint256"}],"payable":false,"type":"function"},{"constant":true,"inputs":[{"name":"","type":"address"}],"name":"canCreateBlocks","outputs":[{"name":"","type":"bool"}],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"voteThreshold","outputs":[{"name":"","type":"uint256"}],"payable":false,"type":"function"},{"constant":true,"inputs":[{"name":"height","type":"uint256"}],"name":"getCanonHash","outputs":[{"name":"","type":"bytes32"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"height","type":"uint256"},{"name":"hash","type":"bytes32"}],"name":"vote","outputs":[],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"addr","type":"address"}],"name":"addBlockMaker","outputs":[],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"addr","type":"address"}],"name":"removeVoter","outputs":[],"payable":false,"type":"function"},{"constant":true,"inputs":[{"name":"height","type":"uint256"},{"name":"n","type":"uint256"}],"name":"getEntry","outputs":[{"name":"","type":"bytes32"}],"payable":false,"type":"function"},{"constant":true,"inputs":[{"name":"addr","type":"address"}],"name":"isVoter","outputs":[{"name":"","type":"bool"}],"payable":false,"type":"function"},{"constant":true,"inputs":[{"name":"","type":"address"}],"name":"canVote","outputs":[{"name":"","type":"bool"}],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"blockMakerCount","outputs":[{"name":"","type":"uint256"}],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"getSize","outputs":[{"name":"","type":"uint256"}],"payable":false,"type":"function"},{"constant":true,"inputs":[{"name":"addr","type":"address"}],"name":"isBlockMaker","outputs":[{"name":"","type":"bool"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"addr","type":"address"}],"name":"addVoter","outputs":[],"payable":false,"type":"function"},{"anonymous":false,"inputs":[{"indexed":true,"name":"sender","type":"address"},{"indexed":false,"name":"blockNumber","type":"uint256"},{"indexed":false,"name":"blockHash","type":"bytes32"}],"name":"Vote","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"","type":"address"}],"name":"AddVoter","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"","type":"address"}],"name":"RemovedVoter","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"","type":"address"}],"name":"AddBlockMaker","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"","type":"address"}],"name":"RemovedBlockMaker","type":"event"}]`
	ABI = `[{"constant":false,"inputs":[{"name":"threshold","type":"uint256"}],"name":"setVoteThreshold","outputs":[],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"addr","type":"address"}],"name":"removeBlockMaker","outputs":[],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"voterCount","outputs":[{"name":"","type":"uint256"}],"payable":false,"type":"function"},{"constant":true,"inputs":[{"name":"","type":"address"}],"name":"canCreateBlocks","outputs":[{"name":"","type":"bool"}],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"voteThreshold","outputs":[{"name":"","type":"uint256"}],"payable":false,"type":"function"},{"constant":true,"inputs":[{"name":"height","type":"uint256"}],"name":"getCanonHash","outputs":[{"name":"","type":"bytes32"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"height","type":"uint256"},{"name":"hash","type":"bytes32"}],"name":"vote","outputs":[],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"addr","type":"address"}],"name":"addBlockMaker","outputs":[],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"governanceAddress","outputs":[{"name":"","type":"address"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"addr","type":"address"}],"name":"removeVoter","outputs":[],"payable":false,"type":"function"},{"constant":true,"inputs":[{"name":"height","type":"uint256"},{"name":"n","type":"uint256"}],"name":"getEntry","outputs":[{"name":"","type":"bytes32"}],"payable":false,"type":"function"},{"constant":true,"inputs":[{"name":"addr","type":"address"}],"name":"isVoter","outputs":[{"name":"","type":"bool"}],"payable":false,"type":"function"},{"constant":true,"inputs":[{"name":"","type":"address"}],"name":"canVote","outputs":[{"name":"","type":"bool"}],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"blockMakerCount","outputs":[{"name":"","type":"uint256"}],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"getSize","outputs":[{"name":"","type":"uint256"}],"payable":false,"type":"function"},{"constant":true,"inputs":[{"name":"addr","type":"address"}],"name":"isBlockMaker","outputs":[{"name":"","type":"bool"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"addr","type":"address"}],"name":"addVoter","outputs":[],"payable":false,"type":"function"},{"anonymous":false,"inputs":[{"indexed":true,"name":"sender","type":"address"},{"indexed":false,"name":"blockNumber","type":"uint256"},{"indexed":false,"name":"blockHash","type":"bytes32"}],"name":"Vote","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"","type":"address"}],"name":"AddVoter","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"","type":"address"}],"name":"RemovedVoter","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"","type":"address"}],"name":"AddBlockMaker","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"","type":"address"}],"name":"RemovedBlockMaker","type":"event"}]`
	
	// > solc --version
	// solc, the solidity compiler commandline interface
	// Version: 0.4.10+commit.f0d539ae.Linux.g++
	//
	// Can be verified with the command line solidity compiler:
	// > solc --bin-runtime --optimize block_voting.sol
	//
	// Note: solidity embeds a hash of the contents and filename in the end of the code. If the last part
	// of the runtime code differs it is very likely that solc has been run against a file with a different
	// name, or a file with different contents (check for windows vs linux newlines).
	RuntimeCode = "6060604052341561000f57600080fd5b5b610a908061001f6000396000f300606060405236156100ee5763ffffffff7c01000000000000000000000000000000000000000000000000000000006000350416631290948581146100f3578063284d163c1461010b57806342169e481461012c578063488099a6146101515780634fe437d514610184578063559c390c146101a957806368bb8bb6146101d157806372a571fc146101ec578063795053d31461020d57806386c1ff681461023c57806398ba676d1461025d578063a7771ee314610288578063adfaa72e146102bb578063cf528985146102ee578063de8fa43114610313578063e814d1c714610338578063f4ab9adf1461036b575b600080fd5b34156100fe57600080fd5b61010960043561038c565b005b341561011657600080fd5b610109600160a060020a03600435166103bd565b005b341561013757600080fd5b61013f610473565b60405190815260200160405180910390f35b341561015c57600080fd5b610170600160a060020a0360043516610479565b604051901515815260200160405180910390f35b341561018f57600080fd5b61013f61048e565b60405190815260200160405180910390f35b34156101b457600080fd5b61013f600435610494565b60405190815260200160405180910390f35b34156101dc57600080fd5b610109600435602435610598565b005b34156101f757600080fd5b610109600160a060020a03600435166106a9565b005b341561021857600080fd5b610220610755565b604051600160a060020a03909116815260200160405180910390f35b341561024757600080fd5b610109600160a060020a036004351661075a565b005b341561026857600080fd5b61013f600435602435610821565b60405190815260200160405180910390f35b341561029357600080fd5b610170600160a060020a0360043516610875565b604051901515815260200160405180910390f35b34156102c657600080fd5b610170600160a060020a0360043516610897565b604051901515815260200160405180910390f35b34156102f957600080fd5b61013f6108ac565b60405190815260200160405180910390f35b341561031e57600080fd5b61013f6108b2565b60405190815260200160405180910390f35b341561034357600080fd5b610170600160a060020a03600435166108b9565b604051901515815260200160405180910390f35b341561037657600080fd5b610109600160a060020a03600435166108db565b005b600160a060020a03331660009081526003602052604090205460ff1615156103b357600080fd5b60018190555b5b50565b33600160a060020a03166042146103d357600080fd5b600454600190116103e357600080fd5b600160a060020a03811660009081526005602052604090205460ff16156103b957600160a060020a03811660009081526005602052604090819020805460ff19169055600480546000190190557f8cee3054364d6799f1c8962580ad61273d9d38ca1ff26516bd1ad23c099a602290829051600160a060020a03909116815260200160405180910390a15b5b5b50565b60025481565b60056020526000908152604090205460ff1681565b60015481565b6000806000806000600186038154811015156104ac57fe5b906000526020600020906002020160005b509250600090505b600183015481101561058c576001830180548491600091849081106104e657fe5b906000526020600020900160005b50548152602080820192909252604090810160009081205485825292869052205410801561055b5750600154836000016000856001018481548110151561053757fe5b906000526020600020900160005b5054815260208101919091526040016000205410155b15610583576001830180548290811061057057fe5b906000526020600020900160005b505491505b5b6001016104c5565b8193505b505050919050565b600160a060020a03331660009081526003602052604081205460ff1615156105bf57600080fd5b600054839010156105df576000805480850301906105dd9082610998565b505b6000805460001985019081106105f157fe5b906000526020600020906002020160005b5060008381526020829052604090205490915015156106455780600101805480600101828161063191906109ca565b916000526020600020900160005b50839055505b6000828152602082905260409081902080546001019055600160a060020a033316907f3d03ba7f4b5227cdb385f2610906e5bcee147171603ec40005b30915ad20e25890439085905191825260208201526040908101905180910390a25b5b505050565b33600160a060020a03166042146106bf57600080fd5b600160a060020a03811660009081526005602052604090205460ff1615156103b957600160a060020a03811660009081526005602052604090819020805460ff191660019081179091556004805490910190557f1a4ce6942f7aa91856332e618fc90159f13a340611a308f5d7327ba0707e568590829051600160a060020a03909116815260200160405180910390a15b5b5b50565b604281565b600160a060020a03331660009081526003602052604090205460ff16151561078157600080fd5b6002546001901161079157600080fd5b600160a060020a03811660009081526003602052604090205460ff16156103b957600160a060020a03811660009081526003602052604090819020805460ff19169055600280546000190190557f183393fc5cffbfc7d03d623966b85f76b9430f42d3aada2ac3f3deabc78899e890829051600160a060020a03909116815260200160405180910390a15b5b5b50565b60008060006001850381548110151561083657fe5b906000526020600020906002020160005b509050806001018381548110151561085b57fe5b906000526020600020900160005b505491505b5092915050565b600160a060020a03811660009081526003602052604090205460ff165b919050565b60036020526000908152604090205460ff1681565b60045481565b6000545b90565b600160a060020a03811660009081526005602052604090205460ff165b919050565b600160a060020a03331660009081526003602052604090205460ff16151561090257600080fd5b600160a060020a03811660009081526003602052604090205460ff1615156103b957600160a060020a03811660009081526003602052604090819020805460ff191660019081179091556002805490910190557f0ad2eca75347acd5160276fe4b5dad46987e4ff4af9e574195e3e9bc15d7e0ff90829051600160a060020a03909116815260200160405180910390a15b5b5b50565b8154818355818115116106a3576002028160020283600052602060002091820191016106a391906109f4565b5b505050565b8154818355818115116106a3576000838152602090206106a3918101908301610a21565b5b505050565b6108b691905b80821115610a1a576000610a116001830182610a42565b506002016109fa565b5090565b90565b6108b691905b80821115610a1a5760008155600101610a27565b5090565b90565b50805460008255906000526020600020908101906103b99190610a21565b5b505600a165627a7a723058206c43cee6b95e2d73ac7bfcf102e3c9be9ad593b65d8dbcc7717ac34ed38486630029"
)

var (
	errSyncing             = fmt.Errorf("Node synchronising with network")
	errCouldNotVote        = fmt.Errorf("Not not configured/allowed to vote")
	errCouldNotCreateBlock = fmt.Errorf("Not not configured/allowed to create block")
)

// BlockVoting is a type of BlockMaker that uses a smart contract
// to determine the canonical chain. Parties that are allowed to
// vote send vote transactions to the voting contract. Based on
// these transactions the parent block is selected where the next
// block will be build on top of.
type BlockVoting struct {
	bc           *core.BlockChain
	cc           *core.ChainConfig
	txpool       *core.TxPool
	syncingChain bool
	mux          *event.TypeMux
	db           ethdb.Database
	am           *accounts.Manager
	gasPrice     *big.Int

	voteSession  *VotingContractSession
	callContract *VotingContractCaller

	bmk *ecdsa.PrivateKey
	vk  *ecdsa.PrivateKey

	pStateMu sync.Mutex
	pState   *pendingState
}

// Vote is posted to the event mux when the BlockVoting instance
// is ordered to send a new vote transaction. Hash is the hash for the
// given number depth.
type Vote struct {
	Hash   common.Hash
	Number *big.Int
	TxHash chan common.Hash
	Err    chan error
}

// CreateBlock is posted to the event mux when the BlockVoting instance
// is ordered to create a new block. Either the hash of the created
// block or an error is returned.
type CreateBlock struct {
	Hash chan common.Hash
	Err  chan error
}

// NewBlockVoting creates a new BlockVoting instance.
// blockMakerKey and/or voteKey can be nil in case this node doesn't create blocks or vote.
// Note, don't forget to call Start.
func NewBlockVoting(bc *core.BlockChain, chainConfig *core.ChainConfig, txpool *core.TxPool, mux *event.TypeMux, db ethdb.Database, accountMgr *accounts.Manager) *BlockVoting {
	bv := &BlockVoting{
		bc:           bc,
		cc:           chainConfig,
		txpool:       txpool,
		mux:          mux,
		db:           db,
		am:           accountMgr,
		syncingChain: false,
	}

	return bv
}

func (bv *BlockVoting) resetPendingState(parent *types.Block) {
	publicState, privateState, err := bv.bc.StateAt(parent.Root())
	if err != nil {
		panic(fmt.Sprintf("State error: %v", err))
	}

	ps := &pendingState{
		parent:        parent,
		publicState:   publicState,
		privateState:  privateState,
		header:        bv.makeHeader(parent),
		gp:            new(core.GasPool),
		ownedAccounts: accountAddressesSet(bv.am.Accounts()),
		alreadyVoted:  false,
	}

	ps.gp.AddGas(ps.header.GasLimit)

	txs := types.NewTransactionsByPriorityAndNonce(bv.txpool.Pending())

	lowGasTxs, failedTxs := ps.applyTransactions(txs, bv.mux, bv.bc, bv.cc)
	bv.txpool.RemoveBatch(lowGasTxs)
	bv.txpool.RemoveBatch(failedTxs)

	bv.pStateMu.Lock()
	bv.pState = ps
	bv.pStateMu.Unlock()
}

func (bv *BlockVoting) makeHeader(parent *types.Block) *types.Header {
	tstart := time.Now()
	tstamp := tstart.Unix()
	if parent.Time().Cmp(new(big.Int).SetInt64(tstamp)) >= 0 {
		tstamp = parent.Time().Int64() + 1
	}
	// this will ensure we're not going off too far in the future
	if now := time.Now().Unix(); tstamp > now+4 {
		wait := time.Duration(tstamp-now) * time.Second
		glog.V(logger.Info).Infoln("We are too far in the future. Waiting for", wait)
		time.Sleep(wait)
	}

	num := parent.Number()
	header := &types.Header{
		Number:     num.Add(num, common.Big1),
		ParentHash: parent.Hash(),
		Difficulty: core.CalcDifficulty(bv.cc, uint64(tstamp), parent.Time().Uint64(), parent.Number(), parent.Difficulty()),
		GasLimit:   core.CalcGasLimit(parent),
		GasUsed:    new(big.Int),
		Time:       big.NewInt(tstamp),
	}

	if bv.bmk != nil {
		header.Coinbase = crypto.PubkeyToAddress(bv.bmk.PublicKey)
	}

	return header
}

// Start runs the event loop.
func (bv *BlockVoting) Start(client *rpc.Client, strat BlockVoteMakerStrategy, voteKey, blockMakerKey *ecdsa.PrivateKey) error {
	bv.bmk = blockMakerKey
	bv.vk = voteKey

	ethClient := ethclient.NewClient(client)
	callContract, err := NewVotingContractCaller(params.QuorumVotingContractAddr, ethClient)
	if err != nil {
		return err
	}
	bv.callContract = callContract

	if voteKey != nil {
		contract, err := NewVotingContract(params.QuorumVotingContractAddr, ethClient)
		if err != nil {
			return err
		}

		auth := bind.NewKeyedTransactor(voteKey)
		bv.voteSession = &VotingContractSession{
			Contract: contract,
			CallOpts: bind.CallOpts{
				Pending: true,
			},
			TransactOpts: bind.TransactOpts{
				From:   auth.From,
				Signer: auth.Signer,
			},
		}
	}

	bv.run(strat)

	return nil
}

func (bv *BlockVoting) run(strat BlockVoteMakerStrategy) {
	if bv.bmk != nil {
		glog.Infof("Node configured for block creation: %s", crypto.PubkeyToAddress(bv.bmk.PublicKey).Hex())
	}
	if bv.vk != nil {
		glog.Infof("Node configured for block voting: %s", crypto.PubkeyToAddress(bv.vk.PublicKey).Hex())
	}

	sub := bv.mux.Subscribe(downloader.StartEvent{},
		downloader.DoneEvent{},
		downloader.FailedEvent{},
		core.ChainHeadEvent{},
		core.TxPreEvent{},
		Vote{},
		CreateBlock{})

	bv.resetPendingState(bv.bc.CurrentBlock())

	go func() {
		defer sub.Unsubscribe()

		strat.Start()

		for {
			select {
			case event, ok := <-sub.Chan():
				if !ok {
					return
				}

				switch e := event.Data.(type) {
				case downloader.StartEvent: // begin synchronising, stop block creation and/or voting
					strat.PauseBlockMaking()
					strat.PauseVoting()
					bv.syncingChain = true
				case downloader.DoneEvent, downloader.FailedEvent: // caught up, or got an error, start block createion and/or voting
					strat.ResumeBlockMaking()
					strat.ResumeVoting()
					bv.syncingChain = false
				case core.ChainHeadEvent: // got a new header, reset pending state
					bv.resetPendingState(e.Block)
				case core.TxPreEvent: // tx entered pool, apply to pending state
					bv.applyTransaction(e.Tx)
				case Vote:
					// node is currently catching up with the chain
					if bv.syncingChain {
						if e.Err != nil {
							e.Err <- errSyncing
						}
						continue
					}

					// node is not configured/allowed to vote
					if !bv.canVote() {
						if e.Err != nil {
							e.Err <- errCouldNotVote
						}
						continue
					}

					// if the vote request doesn't contain the hash/number vote for our local head.
					if e.Hash == (common.Hash{}) || e.Number == nil {
						bv.pStateMu.Lock()
						pBlock := bv.pState.parent
						bv.pStateMu.Unlock()
						e.Hash = pBlock.Hash()
						e.Number = new(big.Int).Add(pBlock.Number(), common.Big1)
					}

					txHash, err := bv.vote(e.Number, e.Hash, e.Err != nil)
					if err == nil && e.TxHash != nil {
						e.TxHash <- txHash
					} else if err != nil && e.Err != nil {
						e.Err <- err
					} else if err != nil {
						if glog.V(logger.Debug) {
							glog.Errorf("Unable to vote: %v", err)
						}
					}

				case CreateBlock:
					if bv.syncingChain {
						if e.Err != nil {
							e.Err <- errSyncing
						}
						continue
					}

					if !bv.canCreateBlocks() {
						if e.Err != nil {
							e.Err <- errCouldNotCreateBlock
						}
						continue
					}

					block, err := bv.createBlock()
					if err == nil && e.Hash != nil {
						e.Hash <- block.Hash()
					} else if err != nil && e.Err != nil {
						e.Err <- err
					} else if err != nil {
						if glog.V(logger.Debug) {
							glog.Errorf("Unable to create block: %v", err)
						}
					}
				}
			}
		}
	}()
}

func (bv *BlockVoting) canCreateBlocks() bool {
	if bv.bmk == nil {
		return false
	}

	r, err := bv.isBlockMaker(crypto.PubkeyToAddress(bv.bmk.PublicKey))
	if err != nil {
		glog.Errorf("Could not determine is node is allowed to create blocks: %v", err)
		return false
	}
	return r
}

func (bv *BlockVoting) canVote() bool {
	if bv.vk == nil {
		return false
	}

	r, err := bv.isVoter(crypto.PubkeyToAddress(bv.vk.PublicKey))
	if err != nil {
		glog.Errorf("Could not determine if node is allowed to vote: %v", err)
		return false
	}
	return r
}

func (bv *BlockVoting) applyTransaction(tx *types.Transaction) {
	acc, _ := tx.From()
	txs := map[common.Address]types.Transactions{acc: types.Transactions{tx}}
	txset := types.NewTransactionsByPriorityAndNonce(txs)

	bv.pStateMu.Lock()
	bv.pState.applyTransactions(txset, bv.mux, bv.bc, bv.cc)
	bv.pStateMu.Unlock()
}

func (bv *BlockVoting) Pending() (*types.Block, *state.StateDB, *state.StateDB) {
	bv.pStateMu.Lock()
	defer bv.pStateMu.Unlock()
	return types.NewBlock(bv.pState.header, bv.pState.txs, nil, bv.pState.receipts), bv.pState.publicState.Copy(), bv.pState.privateState.Copy()
}

func (bv *BlockVoting) createBlock() (*types.Block, error) {
	if bv.bmk == nil {
		return nil, fmt.Errorf("Node not configured for block creation")
	}

	ch, err := bv.canonHash(bv.pState.header.Number.Uint64())
	if err != nil {
		return nil, err
	}

	if ch == (common.Hash{}) {
		return nil, fmt.Errorf("No block with enough votes")
	}

	if ch != bv.pState.parent.Hash() {
		// majority voted for a different head than our pending block was based on
		// reset pending state to the winning block
		if pBlock := bv.bc.GetBlockByHash(ch); pBlock != nil {
			bv.resetPendingState(pBlock)
		}
		return nil, fmt.Errorf("Winning parent block [0x%x] differs than pending block parent [0x%x]", ch, bv.pState.header.Hash())
	}

	bv.pStateMu.Lock()
	defer bv.pStateMu.Unlock()

	state := bv.pState.publicState // shortcut
	header := bv.pState.header
	receipts := bv.pState.receipts

	core.AccumulateRewards(state, header, nil)

	header.Root = state.IntermediateRoot()

	// Quorum blocks contain a signature of the header in the Extra field.
	// This signature is verified during block import and ensures that the
	// block is created by a party that is allowed to create blocks.
	signature, err := crypto.Sign(header.QuorumHash().Bytes(), bv.bmk)
	if err != nil {
		return nil, err
	}
	header.Extra = signature

	// update block hash in receipts and logs now it is available
	for _, r := range receipts {
		for _, l := range r.Logs {
			l.BlockHash = header.Hash()
		}
	}

	header.Bloom = types.CreateBloom(receipts)

	block := types.NewBlock(header, bv.pState.txs, nil, receipts)
	if _, err := bv.bc.InsertChain(types.Blocks{block}); err != nil {
		return nil, err
	}

	bv.mux.Post(core.NewMinedBlockEvent{Block: block})

	return block, nil
}

func (bv *BlockVoting) vote(height *big.Int, hash common.Hash, force bool) (common.Hash, error) {
	if bv.voteSession == nil {
		return common.Hash{}, fmt.Errorf("Node is not configured for voting")
	}
	cv, err := bv.callContract.CanVote(nil, bv.voteSession.TransactOpts.From)
	if err != nil {
		return common.Hash{}, err
	}
	if !cv {
		return common.Hash{}, fmt.Errorf("%s is not allowed to vote", bv.voteSession.TransactOpts.From.Hex())
	}

	if !force {
		if ch, err := bv.canonHash(height.Uint64()); err == nil && ch != (common.Hash{}) {
			// already enough votes, test if this node already has voted, if so don't vote again
			bv.pStateMu.Lock()
			alreadyVoted := bv.pState.alreadyVoted
			bv.pStateMu.Unlock()
			if alreadyVoted {
				return common.Hash{}, fmt.Errorf("Node already voted on this height")
			}
		}
	}

	nonce := bv.txpool.Nonce(bv.voteSession.TransactOpts.From)
	bv.voteSession.TransactOpts.Nonce = new(big.Int).SetUint64(nonce)
	defer func() { bv.voteSession.TransactOpts.Nonce = nil }()

	tx, err := bv.voteSession.Vote(height, hash)
	if err != nil {
		return common.Hash{}, err
	}

	bv.pStateMu.Lock()
	if height.Uint64() == bv.pState.header.Number.Uint64() {
		bv.pState.alreadyVoted = true
	}
	bv.pStateMu.Unlock()

	return tx.Hash(), nil
}

// CanonHash returns the canonical block hash on the given height.
func (bv *BlockVoting) canonHash(height uint64) (common.Hash, error) {
	opts := &bind.CallOpts{Pending: true}
	return bv.callContract.GetCanonHash(opts, new(big.Int).SetUint64(height))
}

// isVoter returns an indication if the given address is allowed
// to vote.
func (bv *BlockVoting) isVoter(addr common.Address) (bool, error) {
	return bv.callContract.IsVoter(nil, addr)
}

// isBlockMaker returns an indication if the given address is allowed
// to make blocks
func (bv *BlockVoting) isBlockMaker(addr common.Address) (bool, error) {
	return bv.callContract.IsBlockMaker(nil, addr)
}

func accountAddressesSet(accounts []accounts.Account) *set.Set {
	accountSet := set.New()
	for _, account := range accounts {
		accountSet.Add(account.Address)
	}
	return accountSet
}

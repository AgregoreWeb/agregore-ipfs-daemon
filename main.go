package main

// Adapted from
// https://github.com/ipfs/go-ipfs/tree/master/docs/examples/go-ipfs-as-a-library

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sync"

	config "github.com/ipfs/go-ipfs-config"
	files "github.com/ipfs/go-ipfs-files"
	icore "github.com/ipfs/interface-go-ipfs-core"

	// icorepath "github.com/ipfs/interface-go-ipfs-core/path"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/ipfs/go-ipfs/core"
	"github.com/ipfs/go-ipfs/core/coreapi"
	"github.com/ipfs/go-ipfs/core/node/libp2p"
	"github.com/ipfs/go-ipfs/plugin/loader" // This package is needed so that all the preloaded plugins are loaded automatically
	"github.com/ipfs/go-ipfs/repo/fsrepo"
	"github.com/libp2p/go-libp2p-core/peer"
)

const ipfsRepoPath = "agregore-ipfs-repo"

/// ------ Setting up the IPFS Repo

func setupPlugins(externalPluginsPath string) error {
	// Load any external plugins if available on externalPluginsPath
	plugins, err := loader.NewPluginLoader(filepath.Join(externalPluginsPath, "plugins"))
	if err != nil {
		return fmt.Errorf("error loading plugins: %s", err)
	}

	// Load preloaded and external plugins
	if err := plugins.Initialize(); err != nil {
		return fmt.Errorf("error initializing plugins: %s", err)
	}

	if err := plugins.Inject(); err != nil {
		return fmt.Errorf("error initializing plugins: %s", err)
	}

	return nil
}

// setupConfig applies custom settings to an IPFS config
func setupConfig(cfg *config.Config) {
	// https://github.com/ipfs/go-ipfs/blob/master/docs/config.md
	// https://github.com/ipfs/go-ipfs/blob/master/docs/experimental-features.md

	// Enable pubsub for better IPNS
	cfg.Ipns.UsePubsub = config.True
	// Disable API and gateway to prevent malicious apps from using
	cfg.Addresses.API = []string{}
	cfg.Addresses.Gateway = []string{}
	// Reduce number of peer connections to reduce resource usage
	// TODO: needs tuning
	cfg.Swarm.ConnMgr.LowWater = 100
	cfg.Swarm.ConnMgr.HighWater = 200
	// Enable NAT workarounds
	cfg.Swarm.RelayClient.Enabled = config.True
	cfg.Swarm.EnableHolePunching = config.True
	// Limit repo size
	cfg.Datastore.StorageMax = "1GiB"
}

func createRepo(path string) error {
	err := os.Mkdir(path, 0755)
	if err != nil {
		return fmt.Errorf("failed to create repo dir: %s", err)
	}

	// Create a config with default options and a 2048 bit key
	cfg, err := config.Init(ioutil.Discard, 2048)
	if err != nil {
		return err
	}

	// Custom settings
	setupConfig(cfg)

	// Create the repo with the config
	err = fsrepo.Init(path, cfg)
	if err != nil {
		return fmt.Errorf("failed to init node: %s", err)
	}

	return nil
}

/// ------ Spawning the node

// Creates an IPFS node and returns its coreAPI
func createNode(ctx context.Context, repoPath string) (icore.CoreAPI, error) {
	// Open the repo
	repo, err := fsrepo.Open(repoPath)
	if err != nil {
		return nil, err
	}

	// Apply custom config, in case this repo was created with an old config
	cfg, err := repo.Config()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve repo config: %w", err)
	}
	setupConfig(cfg)
	err = repo.SetConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to set repo config: %w", err)
	}

	// Construct the node

	nodeOptions := &core.BuildCfg{
		Online:  true,
		Routing: libp2p.DHTOption, // Full DHT node (store and fetch)
		Repo:    repo,
	}

	node, err := core.NewNode(ctx, nodeOptions)
	if err != nil {
		return nil, err
	}

	// Attach the Core API to the constructed node
	return coreapi.NewCoreAPI(node)
}

// Spawns a node on the default repo location, creating it if it doesn't exist
func spawnNode(ctx context.Context) (icore.CoreAPI, error) {
	if err := setupPlugins(ipfsRepoPath); err != nil {
		return nil, err
	}

	// Create repo if needed
	if _, err := os.Stat(ipfsRepoPath); err != nil {
		if os.IsNotExist(err) {
			err := createRepo(ipfsRepoPath)
			if err != nil {
				return nil, err
			}
		} else {
			// Other error: permissions, etc
			return nil, err
		}
	}

	return createNode(ctx, ipfsRepoPath)
}

func connectToPeers(ctx context.Context, ipfs icore.CoreAPI, peers []string) error {
	var wg sync.WaitGroup
	peerInfos := make(map[peer.ID]*peer.AddrInfo, len(peers))
	for _, addrStr := range peers {
		addr, err := ma.NewMultiaddr(addrStr)
		if err != nil {
			return err
		}
		pii, err := peer.AddrInfoFromP2pAddr(addr)
		if err != nil {
			return err
		}
		pi, ok := peerInfos[pii.ID]
		if !ok {
			pi = &peer.AddrInfo{ID: pii.ID}
			peerInfos[pi.ID] = pi
		}
		pi.Addrs = append(pi.Addrs, pii.Addrs...)
	}

	wg.Add(len(peerInfos))
	for _, peerInfo := range peerInfos {
		go func(peerInfo *peer.AddrInfo) {
			defer wg.Done()
			err := ipfs.Swarm().Connect(ctx, *peerInfo)
			if err != nil {
				log.Printf("failed to connect to %s: %s", peerInfo.ID, err)
			}
		}(peerInfo)
	}
	wg.Wait()
	return nil
}

func getUnixfsFile(path string) (files.File, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	st, err := file.Stat()
	if err != nil {
		return nil, err
	}

	f, err := files.NewReaderPathFile(path, file, st)
	if err != nil {
		return nil, err
	}

	return f, nil
}

func getUnixfsNode(path string) (files.Node, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	f, err := files.NewSerialFile(path, false, st)
	if err != nil {
		return nil, err
	}

	return f, nil
}

/// -------

func main() {
	// Getting a IPFS node running

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ipfs, err := spawnNode(ctx)
	if err != nil {
		log.Fatalf("failed to spawn node: %s", err)
	}

	log.Println("IPFS node is running")

	// Let node just run
	_ = ipfs
	select {}
}

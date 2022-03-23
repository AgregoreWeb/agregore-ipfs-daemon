package main

// Adapted from
// https://github.com/ipfs/go-ipfs/tree/master/docs/examples/go-ipfs-as-a-library

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	config "github.com/ipfs/go-ipfs-config"
	files "github.com/ipfs/go-ipfs-files"
	corehttp "github.com/ipfs/go-ipfs/core/corehttp"
	corerepo "github.com/ipfs/go-ipfs/core/corerepo"
	icore "github.com/ipfs/interface-go-ipfs-core"

	// icorepath "github.com/ipfs/interface-go-ipfs-core/path"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/ipfs/go-ipfs/core"
	"github.com/ipfs/go-ipfs/core/coreapi"
	"github.com/ipfs/go-ipfs/core/node/libp2p"
	"github.com/ipfs/go-ipfs/plugin/loader" // This package is needed so that all the preloaded plugins are loaded automatically
	"github.com/ipfs/go-ipfs/repo/fsrepo"
	"github.com/libp2p/go-libp2p-core/peer"

	_ "github.com/mtibben/androiddnsfix"
)

const ipfsRepoPath = "agregore-ipfs-repo"

// Error channels that need to be tracked
var errChs = make([]<-chan error, 0)

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
	wd, err := os.Getwd()
	if err != nil {
		log.Fatalf("couldn't get working directory: %v", err)
	}

	// https://github.com/ipfs/go-ipfs/blob/master/docs/config.md
	// https://github.com/ipfs/go-ipfs/blob/master/docs/experimental-features.md

	// Enable pubsub for better IPNS
	cfg.Ipns.UsePubsub = config.True
	// Disable API to prevent malicious apps from using
	cfg.Addresses.API = []string{}
	// Run gateway on Unix socket
	cfg.Addresses.Gateway = []string{filepath.Join("/unix/", wd, "gateway.sock")}
	cfg.Gateway.Writable = true
	// Reduce number of peer connections to reduce resource usage
	// TODO: needs tuning
	cfg.Swarm.ConnMgr.LowWater = 100
	cfg.Swarm.ConnMgr.HighWater = 200
	// Enable NAT workarounds
	cfg.Swarm.RelayClient.Enabled = config.True
	cfg.Swarm.EnableHolePunching = config.True
	// Limit repo size
	cfg.Datastore.StorageMax = "1GiB"

	// Custom gateway headers
	cfg.Gateway.HTTPHeaders = make(map[string][]string)
	cfg.Gateway.HTTPHeaders["Access-Control-Allow-Methods"] = []string{"GET", "HEAD", "POST", "PUT"}
	cfg.Gateway.HTTPHeaders["Access-Control-Allow-Headers"] = []string{"X-IPFS-Pin"}
	cfg.Gateway.HTTPHeaders["Access-Control-Expose-Headers"] = []string{"IPFS-Hash", "X-IPFS-Path", "X-IPNS-Path", "Etag"}
	cfg.Gateway.HTTPHeaders["Access-Control-Max-Age"] = []string{"86400"}
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
func createNode(ctx context.Context, repoPath string) (icore.CoreAPI, *core.IpfsNode, error) {
	// Open the repo
	repo, err := fsrepo.Open(repoPath)
	if err != nil {
		return nil, nil, err
	}

	// Apply custom config, in case this repo was created with an old config
	cfg, err := repo.Config()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve repo config: %w", err)
	}
	setupConfig(cfg)
	err = repo.SetConfig(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to set repo config: %w", err)
	}

	// Construct the node

	nodeOptions := &core.BuildCfg{
		Online:  true,
		Routing: libp2p.DHTOption, // Full DHT node (store and fetch)
		Repo:    repo,
		// Set PubSub stuff, this was taken from go-ipfs daemon.go
		ExtraOpts: map[string]bool{
			"pubsub": true,
			"ipnsps": true,
		},
	}

	node, err := core.NewNode(ctx, nodeOptions)
	if err != nil {
		return nil, nil, err
	}

	// Set up GC
	// Same thing as --enable-gc
	errc := make(chan error)
	go func() {
		errc <- corerepo.PeriodicGC(ctx, node)
		close(errc)
	}()
	errChs = append(errChs, errc) // Keep track of this channel globally

	// Attach the Core API to the constructed node
	api, err := coreapi.NewCoreAPI(node)
	if err != nil {
		return nil, nil, err
	}
	return api, node, nil
}

// Spawns a node on the default repo location, creating it if it doesn't exist
func spawnNode(ctx context.Context) (icore.CoreAPI, *core.IpfsNode, error) {
	if err := setupPlugins(ipfsRepoPath); err != nil {
		return nil, nil, err
	}

	// Create repo if needed
	if _, err := os.Stat(ipfsRepoPath); err != nil {
		if os.IsNotExist(err) {
			err := createRepo(ipfsRepoPath)
			if err != nil {
				return nil, nil, err
			}
		} else {
			// Other error: permissions, etc
			return nil, nil, err
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
	log.Println("started")

	// Shared context for all IPFS node stuff
	ctx, cancel := context.WithCancel(context.Background())

	ipfs, node, err := spawnNode(ctx)
	if err != nil {
		log.Fatalf("failed to spawn node: %s", err)
	}
	_ = ipfs

	log.Println("IPFS node is running")

	// Start gateway

	opts := []corehttp.ServeOption{
		corehttp.GatewayOption(true, "/ipfs", "/ipns"),
	}
	gatewayAddr, _ := node.Repo.GetConfigKey("Addresses.Gateway")
	gatewayErrC := make(chan error)
	errChs = append(errChs, gatewayErrC) // Add server error to global error tracking
	go func() {
		gatewayErrC <- corehttp.ListenAndServe(node, gatewayAddr.(string), opts...)
	}()
	log.Printf("Gateway listening on %s", gatewayAddr.(string))

	exitCode := 0

	// Wait for server error or process signals like Ctrl-C
	errc := merge(errChs...)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errc:
		log.Printf("fatal error: %v", err)
		exitCode = 1
	case sig := <-sigs:
		log.Printf("terminating due to signal: %v", sig)
		exitCode = 1
	}

	// There was an error, shut things down

	log.Println("starting shutdown...")
	cancel()

	// Let any background processes finish up
	time.Sleep(2 * time.Second)
	log.Println("stopped")

	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

// merge does fan-in of multiple read-only error channels
// taken from http://blog.golang.org/pipelines
// taken from https://github.com/ipfs/go-ipfs/blob/d5ad847e05865e81957c43f526600860c06dbb84/cmd/ipfs/daemon.go#L875
func merge(cs ...<-chan error) <-chan error {
	var wg sync.WaitGroup
	out := make(chan error)

	// Start an output goroutine for each input channel in cs.  output
	// copies values from c to out until c is closed, then calls wg.Done.
	output := func(c <-chan error) {
		for n := range c {
			out <- n
		}
		wg.Done()
	}
	for _, c := range cs {
		if c != nil {
			wg.Add(1)
			go output(c)
		}
	}

	// Start a goroutine to close out once all the output goroutines are
	// done.  This must start after the wg.Add call.
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

# agregore-ipfs-daemon

**Work in progress**


The [go-ipfs](./go-ipfs/) directory is forked from [go-ipfs v0.12.0](https://github.com/ipfs/go-ipfs/tree/v0.12.0), but the important part are the changes in [gateway_handler.go](./go-ipfs/core/corehttp/gateway_handler.go).


## Build

Clone with git and enter the directory. Then run:

```
docker run --rm -v "$PWD":/module makeworld/gomobile-android bind -target=android/arm -javapkg=moe.mauve.agregore.ipfs -o agregore-ipfs-daemon.aar ./gateway
```

*Note: the image is 4.1 GB uncompressed*

## License

This repo is dual-licensed under the MIT and APACHE2 licenses. Please see [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE2](LICENSE-APACHE2) for details.

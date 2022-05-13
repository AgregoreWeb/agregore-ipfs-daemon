package corehttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	golog "log"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	gopath "path"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/antage/eventsource"
	humanize "github.com/dustin/go-humanize"
	"github.com/gabriel-vasile/mimetype"
	"github.com/ipfs/go-cid"
	files "github.com/ipfs/go-ipfs-files"
	keystore "github.com/ipfs/go-ipfs-keystore"
	assets "github.com/ipfs/go-ipfs/assets"
	ke "github.com/ipfs/go-ipfs/core/commands/keyencode"
	dag "github.com/ipfs/go-merkledag"
	mfs "github.com/ipfs/go-mfs"
	path "github.com/ipfs/go-path"
	"github.com/ipfs/go-path/resolver"
	coreiface "github.com/ipfs/interface-go-ipfs-core"
	"github.com/ipfs/interface-go-ipfs-core/options"
	ipath "github.com/ipfs/interface-go-ipfs-core/path"
	"github.com/libp2p/go-libp2p-core/peer"
	routing "github.com/libp2p/go-libp2p-core/routing"
	prometheus "github.com/prometheus/client_golang/prometheus"
)

const (
	ipfsPathPrefix = "/ipfs/"
	ipnsPathPrefix = "/ipns/"

	// CIDv1 for an empty directory
	emptyDirCidStr = "bafybeiczsscdsbs7ffqz55asqdf3smv6klcw3gofszvwlyarci47bgf354"

	pinHeader = "X-IPFS-Pin"
)

var emptyDirCid = cidMustDecode(emptyDirCidStr)

var onlyAscii = regexp.MustCompile("[[:^ascii:]]")

var _ golog.Logger // Keep import around

// HTML-based redirect for errors which can be recovered from, but we want
// to provide hint to people that they should fix things on their end.
var redirectTemplate = template.Must(template.New("redirect").Parse(`<!DOCTYPE html>
<html>
	<head>
		<meta charset="utf-8">
		<meta http-equiv="refresh" content="10;url={{.RedirectURL}}" />
		<link rel="canonical" href="{{.RedirectURL}}" />
	</head>
	<body>
		<pre>{{.ErrorMsg}}</pre><pre>(if a redirect does not happen in 10 seconds, use "{{.SuggestedPath}}" instead)</pre>
	</body>
</html>`))

type redirectTemplateData struct {
	RedirectURL   string
	SuggestedPath string
	ErrorMsg      string
}

// gatewayHandler is a HTTP handler that serves IPFS objects (accessible by default at /ipfs/<path>)
// (it serves requests like GET /ipfs/QmVRzPKPzNtSrEzBFm2UZfxmPAgnaLke4DMcerbsGGSaFe/link)
type gatewayHandler struct {
	config   GatewayConfig
	api      coreiface.CoreAPI
	keystore keystore.Keystore
	id       peer.ID

	// Maps pubsub topics and formats to SSE structs
	eventsources map[string]eventsource.EventSource
	headerBytes  [][]byte

	unixfsGetMetric *prometheus.SummaryVec
}

// StatusResponseWriter enables us to override HTTP Status Code passed to
// WriteHeader function inside of http.ServeContent.  Decision is based on
// presence of HTTP Headers such as Location.
type statusResponseWriter struct {
	http.ResponseWriter
}

func (sw *statusResponseWriter) WriteHeader(code int) {
	// Check if we need to adjust Status Code to account for scheduled redirect
	// This enables us to return payload along with HTTP 301
	// for subdomain redirect in web browsers while also returning body for cli
	// tools which do not follow redirects by default (curl, wget).
	redirect := sw.ResponseWriter.Header().Get("Location")
	if redirect != "" && code == http.StatusOK {
		code = http.StatusMovedPermanently
	}
	sw.ResponseWriter.WriteHeader(code)
}

func newGatewayHandler(c GatewayConfig, api coreiface.CoreAPI, keystore keystore.Keystore, id peer.ID) *gatewayHandler {
	unixfsGetMetric := prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Namespace: "ipfs",
			Subsystem: "http",
			Name:      "unixfs_get_latency_seconds",
			Help:      "The time till the first block is received when 'getting' a file from the gateway.",
		},
		[]string{"gateway"},
	)
	if err := prometheus.Register(unixfsGetMetric); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			unixfsGetMetric = are.ExistingCollector.(*prometheus.SummaryVec)
		} else {
			log.Errorf("failed to register unixfsGetMetric: %v", err)
		}
	}

	i := &gatewayHandler{
		config:          c,
		api:             api,
		keystore:        keystore,
		id:              id,
		eventsources:    make(map[string]eventsource.EventSource),
		unixfsGetMetric: unixfsGetMetric,
	}
	return i
}

func parseIpfsPath(p string) (cid.Cid, string, error) {
	rootPath, err := path.ParsePath(p)
	if err != nil {
		return cid.Cid{}, "", err
	}

	// Check the path.
	rsegs := rootPath.Segments()
	if rsegs[0] != "ipfs" {
		return cid.Cid{}, "", fmt.Errorf("WritableGateway: only ipfs paths supported")
	}

	rootCid, err := cid.Decode(rsegs[1])
	if err != nil {
		return cid.Cid{}, "", err
	}

	return rootCid, path.Join(rsegs[2:]), nil
}

func (i *gatewayHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// the hour is a hard fallback, we don't expect it to happen, but just in case
	ctx, cancel := context.WithTimeout(r.Context(), time.Hour)
	defer cancel()
	r = r.WithContext(ctx)

	defer func() {
		if r := recover(); r != nil {
			log.Error("A panic occurred in the gateway handler!")
			log.Error(r)
			debug.PrintStack()
		}
	}()

	if len(r.URL.RawQuery) > 0 {
		golog.Printf("Gateway: %s %s", r.Method, r.URL.Path+"?"+r.URL.RawQuery)
	} else {
		golog.Printf("Gateway: %s %s", r.Method, r.URL.Path)
	}

	if strings.HasPrefix(r.URL.Path, "/pubsub/") {
		switch r.Method {
		case http.MethodGet:
			i.pubsubGetHandler(w, r)
		case http.MethodPost:
			i.pubsubPostHandler(w, r)
		case http.MethodHead:
			i.pubsubHeadHandler(w, r)
		case http.MethodOptions:
			i.optionsHandler(w, r)
		default:
			http.Error(w, "Method "+r.Method+" not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	if i.config.Writable {
		switch r.Method {
		case http.MethodPost:
			if strings.HasPrefix(r.URL.Path, ipnsPathPrefix) {
				if strings.HasPrefix(r.URL.Path, ipnsPathPrefix+"localhost") {
					i.keyPostHandler(w, r)
				} else {
					i.ipnsPostHandler(w, r)
				}
			} else {
				i.ipfsPostHandler(w, r)
			}
			return
		case http.MethodPut:
			if strings.HasPrefix(r.URL.Path, ipnsPathPrefix) {
				i.ipnsPutHandler(w, r)
			} else {
				i.ipfsPutHandler(w, r)
			}
			return
		case http.MethodDelete:
			if strings.HasPrefix(r.URL.Path, ipnsPathPrefix) {
				if strings.HasPrefix(r.URL.Path, ipnsPathPrefix+"localhost") {
					i.keyDeleteHandler(w, r)
				} else {
					i.ipnsDeleteHandler(w, r)
				}
			} else {
				i.ipfsDeleteHandler(w, r)
			}
			return
		}
	}

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if strings.HasPrefix(r.URL.Path, ipnsPathPrefix+"localhost") {
			i.keyGetHandler(w, r)
		} else {
			i.getOrHeadHandler(w, r)
		}
		return
	case http.MethodOptions:
		i.optionsHandler(w, r)
		return
	}

	errmsg := "Method " + r.Method + " not allowed: "
	var status int
	if !i.config.Writable {
		status = http.StatusMethodNotAllowed
		errmsg = errmsg + "read only access"
		w.Header().Add("Allow", http.MethodGet)
		w.Header().Add("Allow", http.MethodHead)
		w.Header().Add("Allow", http.MethodOptions)
	} else {
		status = http.StatusBadRequest
		errmsg = errmsg + "bad request for " + r.URL.Path
	}
	http.Error(w, errmsg, status)
}

func (i *gatewayHandler) optionsHandler(w http.ResponseWriter, r *http.Request) {
	/*
		OPTIONS is a noop request that is used by the browsers to check
		if server accepts cross-site XMLHttpRequest (indicated by the presence of CORS headers)
		https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS#Preflighted_requests
	*/
	i.addUserHeaders(w) // return all custom headers (including CORS ones, if set)
}

func (i *gatewayHandler) getOrHeadHandler(w http.ResponseWriter, r *http.Request) {
	begin := time.Now()
	urlPath := r.URL.Path
	escapedURLPath := r.URL.EscapedPath()

	// If the gateway is behind a reverse proxy and mounted at a sub-path,
	// the prefix header can be set to signal this sub-path.
	// It will be prepended to links in directory listings and the index.html redirect.
	// TODO: this feature is deprecated and will be removed  (https://github.com/ipfs/go-ipfs/issues/7702)
	prefix := ""
	if prfx := r.Header.Get("X-Ipfs-Gateway-Prefix"); len(prfx) > 0 {
		for _, p := range i.config.PathPrefixes {
			if prfx == p || strings.HasPrefix(prfx, p+"/") {
				prefix = prfx
				break
			}
		}
	}

	i.addUserHeaders(w)

	// HostnameOption might have constructed an IPNS/IPFS path using the Host header.
	// In this case, we need the original path for constructing redirects
	// and links that match the requested URL.
	// For example, http://example.net would become /ipns/example.net, and
	// the redirects and links would end up as http://example.net/ipns/example.net
	requestURI, err := url.ParseRequestURI(r.RequestURI)
	if err != nil {
		webError(w, "failed to parse request path", err, http.StatusInternalServerError)
		return
	}
	originalUrlPath := prefix + requestURI.Path

	// ?uri query param support for requests produced by web browsers
	// via navigator.registerProtocolHandler Web API
	// https://developer.mozilla.org/en-US/docs/Web/API/Navigator/registerProtocolHandler
	// TLDR: redirect /ipfs/?uri=ipfs%3A%2F%2Fcid%3Fquery%3Dval to /ipfs/cid?query=val
	if uriParam := r.URL.Query().Get("uri"); uriParam != "" {
		u, err := url.Parse(uriParam)
		if err != nil {
			webError(w, "failed to parse uri query parameter", err, http.StatusBadRequest)
			return
		}
		if u.Scheme != "ipfs" && u.Scheme != "ipns" {
			webError(w, "uri query parameter scheme must be ipfs or ipns", err, http.StatusBadRequest)
			return
		}
		path := u.Path
		if u.RawQuery != "" { // preserve query if present
			path = path + "?" + u.RawQuery
		}
		http.Redirect(w, r, gopath.Join("/", prefix, u.Scheme, u.Host, path), http.StatusMovedPermanently)
		return
	}

	// Service Worker registration request
	if r.Header.Get("Service-Worker") == "script" {
		// Disallow Service Worker registration on namespace roots
		// https://github.com/ipfs/go-ipfs/issues/4025
		matched, _ := regexp.MatchString(`^/ip[fn]s/[^/]+$`, r.URL.Path)
		if matched {
			err := fmt.Errorf("registration is not allowed for this scope")
			webError(w, "navigator.serviceWorker", err, http.StatusBadRequest)
			return
		}
	}

	parsedPath := ipath.New(urlPath)
	if pathErr := parsedPath.IsValid(); pathErr != nil {
		if prefix == "" && fixupSuperfluousNamespace(w, urlPath, r.URL.RawQuery) {
			// the error was due to redundant namespace, which we were able to fix
			// by returning error/redirect page, nothing left to do here
			return
		}
		// unable to fix path, returning error
		webError(w, "invalid ipfs path", pathErr, http.StatusBadRequest)
		return
	}

	// Resolve path to the final DAG node for the ETag
	resolvedPath, err := i.api.ResolvePath(r.Context(), parsedPath)
	switch err {
	case nil:
	case coreiface.ErrOffline:
		webError(w, "ipfs resolve -r "+escapedURLPath, err, http.StatusServiceUnavailable)
		return
	default:
		if i.servePretty404IfPresent(w, r, parsedPath) {
			return
		}

		webError(w, "ipfs resolve -r "+escapedURLPath, err, http.StatusNotFound)
		return
	}

	dr, err := i.api.Unixfs().Get(r.Context(), resolvedPath)
	if err != nil {
		webError(w, "ipfs cat "+escapedURLPath, err, http.StatusNotFound)
		return
	}

	i.unixfsGetMetric.WithLabelValues(parsedPath.Namespace()).Observe(time.Since(begin).Seconds())

	defer dr.Close()

	var responseEtag string

	// we need to figure out whether this is a directory before doing most of the heavy lifting below
	_, ok := dr.(files.Directory)
	// Also if it's a JSON or HTML directory listing
	jsonListing := r.Header.Get("Accept") == "application/json"

	if ok {
		if jsonListing {
			responseEtag = `"DirIndex-json_CID-` + getV1(resolvedPath.Cid()).String() + `"`
		} else if assets.BindataVersionHash != "" {
			responseEtag = `"DirIndex-` + assets.BindataVersionHash + `_CID-` + getV1(resolvedPath.Cid()).String() + `"`
		}
	} else {
		responseEtag = `"` + getV1(resolvedPath.Cid()).String() + `"`
	}

	// Check etag sent back to us
	if r.Header.Get("If-None-Match") == responseEtag || r.Header.Get("If-None-Match") == `W/`+responseEtag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("X-IPFS-Path", urlPath)
	w.Header().Set("Etag", responseEtag)
	w.Header().Set("IPFS-Hash", getV1(resolvedPath.Cid()).String())

	// set these headers _after_ the error, for we may just not have it
	// and don't want the client to cache a 500 response...
	// and only if it's /ipfs!
	// TODO: break this out when we split /ipfs /ipns routes.
	modtime := time.Now()

	if f, ok := dr.(files.File); ok {
		if strings.HasPrefix(urlPath, ipfsPathPrefix) {
			w.Header().Set("Cache-Control", "public, max-age=29030400, immutable")

			// set modtime to a really long time ago, since files are immutable and should stay cached
			modtime = time.Unix(1, 0)
		}

		urlFilename := r.URL.Query().Get("filename")
		var name string
		if urlFilename != "" {
			disposition := "inline"
			if r.URL.Query().Get("download") == "true" {
				disposition = "attachment"
			}
			utf8Name := url.PathEscape(urlFilename)
			asciiName := url.PathEscape(onlyAscii.ReplaceAllLiteralString(urlFilename, "_"))
			w.Header().Set("Content-Disposition", fmt.Sprintf("%s; filename=\"%s\"; filename*=UTF-8''%s", disposition, asciiName, utf8Name))
			name = urlFilename
		} else {
			name = getFilename(urlPath)
		}
		i.serveFile(w, r, name, modtime, f)
		return
	}
	dir, ok := dr.(files.Directory)
	if !ok {
		internalWebError(w, fmt.Errorf("unsupported file type"))
		return
	}

	idx, err := i.api.Unixfs().Get(r.Context(), ipath.Join(resolvedPath, "index.html"))
	switch err.(type) {
	case nil:
		dirwithoutslash := urlPath[len(urlPath)-1] != '/'
		goget := r.URL.Query().Get("go-get") == "1"
		if dirwithoutslash && !goget {
			// See comment above where originalUrlPath is declared.
			suffix := "/"
			if r.URL.RawQuery != "" {
				// preserve query parameters
				suffix = suffix + "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, originalUrlPath+suffix, 302)
			return
		}

		f, ok := idx.(files.File)
		if !ok {
			internalWebError(w, files.ErrNotReader)
			return
		}

		if r.URL.Query().Has("noResolve") {
			// This means don't serve index.html
			break
		}

		// static index.html → no need to generate dynamic dir-index-html
		// replace mutable DirIndex Etag with immutable dir CID
		w.Header().Set("Etag", `"`+getV1(resolvedPath.Cid()).String()+`"`)

		// write to request
		i.serveFile(w, r, "index.html", modtime, f)
		return
	case resolver.ErrNoLink:
		// no index.html; noop
	default:
		internalWebError(w, err)
		return
	}

	// See statusResponseWriter.WriteHeader
	// and https://github.com/ipfs/go-ipfs/issues/7164
	// Note: this needs to occur before listingTemplate.Execute otherwise we get
	// superfluous response.WriteHeader call from prometheus/client_golang
	if w.Header().Get("Location") != "" {
		w.WriteHeader(http.StatusMovedPermanently)
		return
	}

	if jsonListing {
		// Directory listing should be returned as a JSON array
		// Directories end with a slash

		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodHead {
			return
		}

		listing := make([]string, 0)
		dirit := dir.Entries()
		for dirit.Next() {
			name := dirit.Name()
			if _, ok := dirit.Node().(files.Directory); ok {
				name += "/"
			}
			listing = append(listing, name)
		}
		if dirit.Err() != nil {
			internalWebError(w, dirit.Err())
			return
		}

		jsonBytes, err := json.Marshal(&listing)
		if err != nil {
			internalWebError(w, err)
			return
		}
		w.Write(jsonBytes)
		return
	}

	// A HTML directory index will be presented, be sure to set the correct
	// type instead of relying on autodetection (which may fail).
	w.Header().Set("Content-Type", "text/html")
	if r.Method == http.MethodHead {
		return
	}

	// storage for directory listing
	var dirListing []directoryItem
	dirit := dir.Entries()
	for dirit.Next() {
		size := "?"
		if s, err := dirit.Node().Size(); err == nil {
			// Size may not be defined/supported. Continue anyways.
			size = humanize.Bytes(uint64(s))
		}

		resolved, err := i.api.ResolvePath(r.Context(), ipath.Join(resolvedPath, dirit.Name()))
		if err != nil {
			internalWebError(w, err)
			return
		}
		hash := getV1(resolved.Cid()).String()

		// See comment above where originalUrlPath is declared.
		di := directoryItem{
			Size:      size,
			Name:      dirit.Name(),
			Path:      gopath.Join(originalUrlPath, dirit.Name()),
			Hash:      hash,
			ShortHash: shortHash(hash),
		}
		dirListing = append(dirListing, di)
	}
	if dirit.Err() != nil {
		internalWebError(w, dirit.Err())
		return
	}

	// construct the correct back link
	// https://github.com/ipfs/go-ipfs/issues/1365
	var backLink string = originalUrlPath

	// don't go further up than /ipfs/$hash/
	pathSplit := path.SplitList(urlPath)
	switch {
	// keep backlink
	case len(pathSplit) == 3: // url: /ipfs/$hash

	// keep backlink
	case len(pathSplit) == 4 && pathSplit[3] == "": // url: /ipfs/$hash/

	// add the correct link depending on whether the path ends with a slash
	default:
		if strings.HasSuffix(backLink, "/") {
			backLink += "./.."
		} else {
			backLink += "/.."
		}
	}

	size := "?"
	if s, err := dir.Size(); err == nil {
		// Size may not be defined/supported. Continue anyways.
		size = humanize.Bytes(uint64(s))
	}

	hash := getV1(resolvedPath.Cid()).String()

	// Gateway root URL to be used when linking to other rootIDs.
	// This will be blank unless subdomain or DNSLink resolution is being used
	// for this request.
	var gwURL string

	// Get gateway hostname and build gateway URL.
	if h, ok := r.Context().Value("gw-hostname").(string); ok {
		gwURL = "//" + h
	} else {
		gwURL = ""
	}

	dnslink := hasDNSLinkOrigin(gwURL, urlPath)

	// See comment above where originalUrlPath is declared.
	tplData := listingTemplateData{
		GatewayURL:  gwURL,
		DNSLink:     dnslink,
		Listing:     dirListing,
		Size:        size,
		Path:        urlPath,
		Breadcrumbs: breadcrumbs(urlPath, dnslink),
		BackLink:    backLink,
		Hash:        hash,
	}

	err = listingTemplate.Execute(w, tplData)
	if err != nil {
		internalWebError(w, err)
		return
	}
}

func (i *gatewayHandler) serveFile(w http.ResponseWriter, req *http.Request, name string, modtime time.Time, file files.File) {
	size, err := file.Size()
	if err != nil {
		http.Error(w, "cannot serve files with unknown sizes", http.StatusBadGateway)
		return
	}

	content := &lazySeeker{
		size:   size,
		reader: file,
	}

	var ctype string
	if _, isSymlink := file.(*files.Symlink); isSymlink {
		// We should be smarter about resolving symlinks but this is the
		// "most correct" we can be without doing that.
		ctype = "inode/symlink"
	} else {
		ctype = mime.TypeByExtension(gopath.Ext(name))
		if ctype == "" {
			// uses https://github.com/gabriel-vasile/mimetype library to determine the content type.
			// Fixes https://github.com/ipfs/go-ipfs/issues/7252
			mimeType, err := mimetype.DetectReader(content)
			if err != nil {
				http.Error(w, fmt.Sprintf("cannot detect content-type: %s", err.Error()), http.StatusInternalServerError)
				return
			}

			ctype = mimeType.String()
			_, err = content.Seek(0, io.SeekStart)
			if err != nil {
				http.Error(w, "seeker can't seek", http.StatusInternalServerError)
				return
			}
		}
		// Strip the encoding from the HTML Content-Type header and let the
		// browser figure it out.
		//
		// Fixes https://github.com/ipfs/go-ipfs/issues/2203
		if strings.HasPrefix(ctype, "text/html;") {
			ctype = "text/html"
		}
	}
	w.Header().Set("Content-Type", ctype)

	w = &statusResponseWriter{w}
	http.ServeContent(w, req, name, modtime, content)
}

func (i *gatewayHandler) servePretty404IfPresent(w http.ResponseWriter, r *http.Request, parsedPath ipath.Path) bool {
	resolved404Path, ctype, err := i.searchUpTreeFor404(r, parsedPath)
	if err != nil {
		return false
	}

	dr, err := i.api.Unixfs().Get(r.Context(), resolved404Path)
	if err != nil {
		return false
	}
	defer dr.Close()

	f, ok := dr.(files.File)
	if !ok {
		return false
	}

	size, err := f.Size()
	if err != nil {
		return false
	}

	log.Debugf("using pretty 404 file for %s", parsedPath.String())
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.WriteHeader(http.StatusNotFound)
	_, err = io.CopyN(w, f, size)
	return err == nil
}

// rootFromCid returns an MFS root from the CID of an existing directory.
// It returns false if an error was sent to the user.
func (i *gatewayHandler) rootFromCid(w http.ResponseWriter, r *http.Request, rootCid cid.Cid) (*mfs.Root, bool) {
	ctx := r.Context()
	ds := i.api.Dag()

	// Resolve the old root.

	rnode, err := ds.Get(ctx, rootCid)
	if err != nil {
		webError(w, "WritableGateway: Could not create DAG from request", err, http.StatusInternalServerError)
		return nil, false
	}

	pbnd, ok := rnode.(*dag.ProtoNode)
	if !ok {
		webError(w, "Cannot read non protobuf nodes through gateway", dag.ErrNotProtobuf, http.StatusBadRequest)
		return nil, false
	}

	// Create root

	root, err := mfs.NewRoot(ctx, ds, pbnd, nil)
	if err != nil {
		webError(w, "WritableGateway: failed to create MFS root", err, http.StatusBadRequest)
		return nil, false
	}
	return root, true
}

// addFileToDir adds a file to an existing MFS root. It returns false if
// an error was sent to the user. Call finalizeDir after all files are added,
// to make sure they've been added succesfully.
//
// path can begin with a slash but doesn't have to.
func (i *gatewayHandler) addFileToDir(
	w http.ResponseWriter, r *http.Request,
	root *mfs.Root, path string, file io.ReadCloser, pin bool) bool {

	ctx := r.Context()
	ds := i.api.Dag()

	// Create the new file.

	newFilePath, err := i.api.Unixfs().Add(
		ctx,
		files.NewReaderFile(file),
		options.Unixfs.CidVersion(1),
		options.Unixfs.Pin(pin),
	)
	if err != nil {
		webError(w, "WritableGateway: could not create DAG from request", err, http.StatusInternalServerError)
		return false
	}

	newFile, err := ds.Get(ctx, newFilePath.Cid())
	if err != nil {
		webError(w, "WritableGateway: failed to resolve new file", err, http.StatusInternalServerError)
		return false
	}

	// Patch the file into the root

	newDirectory, newFileName := gopath.Split(path)

	// Shouldn't begin with slash
	newDirectory = strings.TrimLeft(newDirectory, "/")

	if newDirectory != "" {
		err := mfs.Mkdir(root, newDirectory, mfs.MkdirOpts{Mkparents: true, Flush: false})
		if err != nil {
			webError(w, "WritableGateway: failed to create MFS directory", err, http.StatusInternalServerError)
			return false
		}
	}
	dirNode, err := mfs.Lookup(root, newDirectory)
	if err != nil {
		webError(w, "WritableGateway: failed to lookup directory", err, http.StatusInternalServerError)
		return false
	}
	dir, ok := dirNode.(*mfs.Directory)
	if !ok {
		http.Error(w, "WritableGateway: target directory is not a directory", http.StatusBadRequest)
		return false
	}
	err = dir.Unlink(newFileName)
	switch err {
	case os.ErrNotExist, nil:
	default:
		webError(w, "WritableGateway: failed to replace existing file", err, http.StatusBadRequest)
		return false
	}
	err = dir.AddChild(newFileName, newFile)
	if err != nil {
		webError(w, "WritableGateway: failed to link file into directory", err, http.StatusInternalServerError)
		return false
	}

	return true
}

// addIpfsPathToDir adds a file or dir to an existing MFS root, specified using
// a path like /ipfs/<CID>/a
//
// dstPath is the destination path. If it ends with a slash it will be the
// containing directory for the ipfs path. Parent dirs will be created as needed.
// If it doesn't end with a slash then it will be the name of the ipfs path.
//
// This func returns false if an error was sent to the user. Call finalizeDir after all
// files are added, to make sure they've been added succesfully.
func (i *gatewayHandler) addIpfsPathToDir(
	w http.ResponseWriter, r *http.Request,
	root *mfs.Root, ipfsPath ipath.Path, dstPath string) bool {

	ctx := r.Context()

	// dstPath can't end with a directory name
	if dstPath[len(dstPath)-1] == '/' {
		dstPath += gopath.Base(ipfsPath.String())
	}

	nd, err := i.api.ResolveNode(ctx, ipfsPath)
	if err != nil {
		webError(w, "WritableGateway: failed to resolve node", err, http.StatusInternalServerError)
		return false
	}

	newDirectory, newFileName := gopath.Split(dstPath)

	if newDirectory != "/" && newDirectory != "" {
		err := mfs.Mkdir(root, newDirectory, mfs.MkdirOpts{Mkparents: true, Flush: false})
		if err != nil {
			webError(w, "WritableGateway: failed to create MFS directory", err, http.StatusInternalServerError)
			return false
		}
	}

	dirNode, err := mfs.Lookup(root, newDirectory)
	if err != nil {
		webError(w, "WritableGateway: failed to lookup directory", err, http.StatusInternalServerError)
		return false
	}
	dir, ok := dirNode.(*mfs.Directory)
	if !ok {
		http.Error(w, "WritableGateway: target directory is not a directory", http.StatusBadRequest)
		return false
	}
	err = dir.Unlink(newFileName)
	switch err {
	case os.ErrNotExist, nil:
	default:
		webError(w, "WritableGateway: failed to replace existing file", err, http.StatusBadRequest)
		return false
	}

	err = mfs.PutNode(root, dstPath, nd)
	if err != nil {
		webError(w, "WritableGateway: failed to put node in MFS directory", err, http.StatusInternalServerError)
		return false
	}

	return true
}

func (i *gatewayHandler) removePathFromDir(
	w http.ResponseWriter, r *http.Request,
	root *mfs.Root, path string) bool {

	directory, filename := gopath.Split(path)

	// lookup the parent directory

	parentNode, err := mfs.Lookup(root, directory)
	if err != nil {
		webError(w, "WritableGateway: failed to look up parent", err, http.StatusInternalServerError)
		return false
	}

	parent, ok := parentNode.(*mfs.Directory)
	if !ok {
		http.Error(w, "WritableGateway: parent is not a directory", http.StatusInternalServerError)
		return false
	}

	// delete the file

	switch parent.Unlink(filename) {
	case nil, os.ErrNotExist:
	default:
		webError(w, "WritableGateway: failed to remove file", err, http.StatusInternalServerError)
		return false
	}
	return true
}

// finalizeDir finalizes that the provided root directory, confirming that all files
// were added successfully. It returns false if an error was sent to the user.
func (i *gatewayHandler) finalizeDir(w http.ResponseWriter, root *mfs.Root) (cid.Cid, bool) {
	node, err := root.GetDirectory().GetNode()
	if err != nil {
		webError(w, "WritableGateway: failed to finalize", err, http.StatusInternalServerError)
		return cid.Cid{}, false
	}
	return node.Cid(), true
}

// addFilesFromForm reads from multipart form data, and adds those files to an existing directory.
// It returns false if an error was sent to the user.
//
// If pin is true then the individual files will be pinned. Pinning the returned
// directory CID or not is up to the caller.
//
// subdir can be "" or "/" to add files to the root.
func (i *gatewayHandler) addFilesFromForm(
	w http.ResponseWriter, r *http.Request,
	dir cid.Cid, subdir string, mpr *multipart.Reader, pin bool) (cid.Cid, bool) {

	// Get dir
	root, ok := i.rootFromCid(w, r, dir)
	if !ok {
		// Sending error to client is handled in the func
		return cid.Cid{}, false
	}

	// Iterate through files
	for {
		part, err := mpr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			internalWebError(w, err)
			return cid.Cid{}, false
		}
		// Only files with the key "file" are valid
		if part.FormName() != "file" {
			continue
		}

		if ok := i.addFileToDir(w, r, root, gopath.Join(subdir, part.FileName()), part, pin); !ok {
			return cid.Cid{}, false
		}
	}

	ncid, ok := i.finalizeDir(w, root)
	if !ok {
		return cid.Cid{}, false
	}
	return ncid, true
}

func (i *gatewayHandler) ipfsPostHandler(w http.ResponseWriter, r *http.Request) {
	i.addUserHeaders(w)

	mpr, err := r.MultipartReader()
	if err != nil && !errors.Is(err, http.ErrNotMultipart) {
		// Unexpected error
		internalWebError(w, err)
		return
	}

	shouldPin := r.Header.Get(pinHeader) != ""
	isDir := mpr != nil

	var cidStr string
	if mpr == nil {
		// Add just a single file
		p, err := i.api.Unixfs().Add(
			r.Context(),
			files.NewReaderFile(r.Body),
			options.Unixfs.CidVersion(1),
			options.Unixfs.Pin(shouldPin),
		)
		if err != nil {
			internalWebError(w, err)
			return
		}
		cidStr = getV1(p.Cid()).String()
	} else {
		// Add multiple files from the form data

		newCid, ok := i.addFilesFromForm(w, r, emptyDirCid, "", mpr, false)
		if !ok {
			// Sending error to client is handled in the func
			return
		}
		// Convert to CIDv1 first if needed
		cidStr = getV1(newCid).String()

		if shouldPin {
			// Pin dir
			err = i.api.Pin().Add(r.Context(), ipath.IpfsPath(newCid))
			if err != nil {
				// Set header so CID is known to client and can be used, or pinning
				// can be tried again
				w.Header().Set("IPFS-Hash", cidStr)
				webError(w, "WritableGateway: failed to pin directory of files", err,
					http.StatusInternalServerError)
				return
			}
		}
	}

	createdPath := "ipfs://" + cidStr
	if isDir {
		createdPath += "/"
	}
	w.Header().Set("IPFS-Hash", cidStr)
	w.Header().Set("Location", createdPath)
	w.WriteHeader(http.StatusCreated)
}

func (i *gatewayHandler) ipfsPutHandler(w http.ResponseWriter, r *http.Request) {
	i.addUserHeaders(w)

	mpr, err := r.MultipartReader()
	if err != nil && !errors.Is(err, http.ErrNotMultipart) {
		// Unexpected error
		internalWebError(w, err)
		return
	}

	// Parse the path
	rootCid, newPath, err := parseIpfsPath(r.URL.Path)
	if err != nil {
		webError(w, "WritableGateway: failed to parse the path", err, http.StatusBadRequest)
		return
	}
	if mpr == nil && (newPath == "" || newPath == "/") {
		// Empty path is allowed when uploading multiple files
		http.Error(w, "WritableGateway: empty path", http.StatusBadRequest)
		return
	}

	shouldPin := r.Header.Get(pinHeader) != ""
	isDir := mpr != nil

	var newCid cid.Cid
	if mpr == nil {
		// Add just a single file to the directory

		root, ok := i.rootFromCid(w, r, rootCid)
		if !ok {
			// Sending error to client is handled in the func
			return
		}
		if ok := i.addFileToDir(w, r, root, newPath, r.Body, false); !ok {
			return
		}
		newCid, ok = i.finalizeDir(w, root)
		if !ok {
			return
		}
	} else {
		// Add multiple files from the form data

		var ok bool
		newCid, ok = i.addFilesFromForm(w, r, rootCid, newPath, mpr, false)
		if !ok {
			// Sending error to client is handled in the func
			return
		}
	}

	cidStr := getV1(newCid).String()

	if shouldPin {
		// Pin dir
		err = i.api.Pin().Add(r.Context(), ipath.IpfsPath(newCid))
		if err != nil {
			// Set header so CID is known to client and can be used, or pinning
			// can be tried again
			w.Header().Set("IPFS-Hash", cidStr)
			webError(w, "WritableGateway: failed to pin directory of files", err,
				http.StatusInternalServerError)
			return
		}
	}

	createdPath := "ipfs:/" + gopath.Join("/", cidStr, newPath)
	if isDir {
		createdPath += "/"
	}
	w.Header().Set("IPFS-Hash", cidStr)
	w.Header().Set("Location", createdPath)
	w.WriteHeader(http.StatusCreated)
}

type stringsCloser struct {
	*strings.Reader
	closeFunc func() error
}

func (sc *stringsCloser) Close() error {
	return sc.closeFunc()
}

func (i *gatewayHandler) ipnsPutHandler(w http.ResponseWriter, r *http.Request) {
	mpr, err := r.MultipartReader()
	if err != nil && !errors.Is(err, http.ErrNotMultipart) {
		// Unexpected error
		internalWebError(w, err)
		return
	}

	var cidStr string

	if mpr == nil {
		// Add just a single file
		p, err := i.api.Unixfs().Add(
			r.Context(), files.NewReaderFile(r.Body), options.Unixfs.CidVersion(1),
		)
		if err != nil {
			internalWebError(w, err)
			return
		}
		cidStr = p.Cid().String()
	} else {
		// Add multiple files from the form data

		// Don't pin because ipnsPostHandler will pin later if everything is successful
		newCid, ok := i.addFilesFromForm(w, r, emptyDirCid, "", mpr, false)
		if !ok {
			// Sending error to client is handled in the func
			return
		}
		cidStr = newCid.String()
	}

	// Take the CID and simulate an IPNS POST request with it

	if mpr != nil {
		// Remove ending slash so that files go inside directory specified
		r.URL.Path = strings.TrimRight(r.URL.Path, "/")
	}

	r.Body = &stringsCloser{strings.NewReader(cidStr), func() error { return r.Body.Close() }}
	i.ipnsPostHandler(w, r)
}

func (i *gatewayHandler) ipfsDeleteHandler(w http.ResponseWriter, r *http.Request) {
	i.addUserHeaders(w)

	rootCid, newPath, err := parseIpfsPath(r.URL.Path)
	if err != nil {
		webError(w, "WritableGateway: failed to parse the path", err, http.StatusBadRequest)
		return
	}
	if newPath == "" || newPath == "/" {
		// Unpin the CID instead of removing any files.

		err := i.api.Pin().Rm(r.Context(), ipath.IpfsPath(rootCid))
		if err != nil {
			webError(w, "WritableGateway: failed to unpin directory of files", err,
				http.StatusInternalServerError)
			return
		}
		// Success
		w.Header().Set("IPFS-Hash", getV1(rootCid).String())
		return
	}

	shouldPin := r.Header.Get(pinHeader) != ""

	root, ok := i.rootFromCid(w, r, rootCid)
	if !ok {
		return
	}
	if !i.removePathFromDir(w, r, root, newPath) {
		return
	}
	newCid, ok := i.finalizeDir(w, root)
	if !ok {
		return
	}
	cidStr := getV1(newCid).String()

	if shouldPin {
		// Pin dir
		err = i.api.Pin().Add(r.Context(), ipath.IpfsPath(newCid))
		if err != nil {
			// Set header so CID is known to client and can be used, or pinning
			// can be tried again
			w.Header().Set("IPFS-Hash", cidStr)
			webError(w, "WritableGateway: failed to pin directory of files", err,
				http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("IPFS-Hash", cidStr)
	w.Header().Set("Location", "ipfs:/"+gopath.Join("/"+cidStr, gopath.Dir(newPath))+"/")
	// note: StatusCreated is technically correct here as we created a new resource.
	w.WriteHeader(http.StatusCreated)
}

func decodeIpnsPath(w http.ResponseWriter, r *http.Request) (
	ipnsPath, // part after key, no leading slash
	keyFromPath string, // full public key, the part after /ipns/
	ok bool,
) {
	rootPath, err := path.ParsePath(r.URL.Path)
	if err != nil {
		webError(w, "WritableGateway: failed to parse the path", err, http.StatusBadRequest)
		return
	}
	segs := rootPath.Segments()
	if len(segs) < 2 {
		webError(w, "WritableGateway: no IPNS key name specified", err, http.StatusBadRequest)
		return
	}
	if len(segs) == 2 {
		keyFromPath = segs[1]
	} else {
		keyFromPath = segs[1]
		// Path is there
		ipnsPath = strings.Join(segs[2:], "/")
		if r.URL.Path[len(r.URL.Path)-1] == '/' {
			ipnsPath += "/"
		}
	}
	ok = true
	return
}

func decodeIpnsKeyURL(w http.ResponseWriter, r *http.Request) (
	ipnsPath, // part after key, no leading slash
	keyName string, // the custom name of the key
	ok bool,
) {
	rootPath, err := path.ParsePath(r.URL.Path)
	if err != nil {
		webError(w, "WritableGateway: failed to parse the path", err, http.StatusBadRequest)
		return
	}
	segs := rootPath.Segments()
	if len(segs) < 2 {
		webError(w, "WritableGateway: no IPNS key name specified", err, http.StatusBadRequest)
		return
	}
	if len(segs) > 2 {
		// Path is there
		ipnsPath = strings.Join(segs[2:], "/")
		if r.URL.Path[len(r.URL.Path)-1] == '/' {
			ipnsPath += "/"
		}
	}

	keyName = r.URL.Query().Get("key")
	if keyName == "" {
		webError(w,
			"WritableGateway: localhost specified as IPNS key but no key param in query string",
			nil, http.StatusBadRequest,
		)
		return
	}
	ok = true
	return
}

func (i *gatewayHandler) keyDeleteHandler(w http.ResponseWriter, r *http.Request) {
	_, keyName, ok := decodeIpnsKeyURL(w, r)
	if !ok {
		return
	}

	i.addUserHeaders(w)

	has, err := i.keystore.Has(keyName)
	if err != nil {
		internalWebError(w, err)
		return
	}
	if !has {
		// Key doesn't exist and so won't resolve to anything
		// So no files can be deleted from it
		webError(w, "Key does not exist", nil, http.StatusBadRequest)
		return
	}

	// Turn key name into string representation of public key
	sk, err := i.keystore.Get(keyName)
	if err != nil {
		internalWebError(w, err)
		return
	}
	pk := sk.GetPublic()
	pid, err := peer.IDFromPublicKey(pk)
	if err != nil {
		internalWebError(w, err)
		return
	}
	keyEnc, err := ke.KeyEncoderFromString("base36") // Default encoding
	if err != nil {
		internalWebError(w, err)
		return
	}
	keyStr := keyEnc.FormatID(pid)

	// Get current IPFS path and CID

	// This is our key so it should resolve instantly
	// If it doesn't that likely means that the key never pointed to anything
	// and unpinning can be skipped.
	// Set a short context to make resolution give up if it doesn't happen right away
	resolveCtx, _ := context.WithTimeout(r.Context(), 1*time.Second)

	resolvedPath, err := i.api.Name().Resolve(resolveCtx, "/ipns/"+keyStr)

	// Whether it errored or not, delete the key now
	err2 := i.keystore.Delete(keyName)
	if err2 != nil {
		webError(w, "WritableGateway: failed to delete key", err, http.StatusInternalServerError)
		return
	}

	if err != nil {
		// Error resolving key
		// Most likely key never pointed to anything, not a real error
		// Skip unpinning
		return
	}

	resolvedCidStr := strings.Split(resolvedPath.String(), "/")[2]
	resolvedCid := cidMustDecode(resolvedCidStr)

	// Unpin content of this key
	err = i.api.Pin().Rm(r.Context(), ipath.IpfsPath(resolvedCid))
	if err != nil {
		webError(w, "WritableGateway: failed to unpin new content", err, http.StatusInternalServerError)
		return
	}
}

func (i *gatewayHandler) ipnsDeleteHandler(w http.ResponseWriter, r *http.Request) {
	ipnsPath, keyFromPath, ok := decodeIpnsPath(w, r)
	if !ok {
		return
	}

	i.addUserHeaders(w)

	if ipnsPath == "" || ipnsPath == "/" {
		http.Error(w, "WritableGateway: empty path", http.StatusBadRequest)
		return
	}

	// Remove trailing slash from ipnsPath if it exists
	// Otherwise directories won't be removed
	ipnsPath = strings.TrimRight(ipnsPath, "/")

	// Get current IPFS path and CID
	resolvedPath, err := i.api.Name().Resolve(r.Context(), "/ipns/"+keyFromPath)
	if err != nil {
		webError(w, "WritableGateway: failed to resolve name", err, http.StatusInternalServerError)
		return
	}
	resolvedCidStr := strings.Split(resolvedPath.String(), "/")[2]
	resolvedCid := cidMustDecode(resolvedCidStr)

	// Remove file/dir

	root, ok := i.rootFromCid(w, r, resolvedCid)
	if !ok {
		return
	}
	if !i.removePathFromDir(w, r, root, ipnsPath) {
		return
	}
	newCid, ok := i.finalizeDir(w, root)
	if !ok {
		return
	}

	// Publish new path

	ipnsEntry, err := i.api.Name().Publish(
		r.Context(), ipath.IpfsPath(newCid),
		options.Name.AllowOffline(true), options.Name.Key(keyFromPath),
	)
	if err != nil {
		webError(w, "WritableGateway: failed to publish path", err, http.StatusInternalServerError)
		return
	}

	// Successfully published new path
	// Pin content and unpin old

	err = i.api.Pin().Add(r.Context(), ipath.IpfsPath(newCid))
	if err != nil {
		webError(w, "WritableGateway: name published but failed to pin new content", err,
			http.StatusInternalServerError)
		return
	}
	if !getV1(resolvedCid).Equals(emptyDirCid) {
		// There was something previously there to unpin
		err = i.api.Pin().Rm(r.Context(), ipath.IpfsPath(resolvedCid))
		if err != nil {
			webError(w, "WritableGateway: name published but failed to unpin new content", err,
				http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("X-IPNS-Path", gopath.Join("/ipns/", ipnsEntry.Name(), gopath.Dir(ipnsPath)))
}

func (i *gatewayHandler) keyGetHandler(w http.ResponseWriter, r *http.Request) {
	ipnsPath, keyName, ok := decodeIpnsKeyURL(w, r)
	if !ok {
		return
	}

	i.addUserHeaders(w)

	sk, err := i.keystore.Get(keyName)
	if errors.Is(err, keystore.ErrNoSuchKey) {
		// Key with provided name doesn't exist
		http.NotFound(w, r)
		return
	}
	if err != nil {
		// Other error
		internalWebError(w, err)
		return
	}

	// Turn key name into string representation of public key
	pk := sk.GetPublic()
	keyID, err := peer.IDFromPublicKey(pk)
	if err != nil {
		internalWebError(w, err)
		return
	}
	keyEnc, err := ke.KeyEncoderFromString("base36") // Default encoding
	if err != nil {
		internalWebError(w, err)
		return
	}

	// Redirect to full key path
	redirLoc := "ipns://" + keyEnc.FormatID(keyID)
	if len(ipnsPath) > 0 {
		redirLoc = "ipns://" + keyEnc.FormatID(keyID) + "/" + ipnsPath
	}
	http.Redirect(w, r, redirLoc, http.StatusFound)
}

func (i *gatewayHandler) keyPostHandler(w http.ResponseWriter, r *http.Request) {
	_, keyName, ok := decodeIpnsKeyURL(w, r)
	if !ok {
		return
	}

	i.addUserHeaders(w)

	has, err := i.keystore.Has(keyName)
	if err != nil {
		internalWebError(w, err)
		return
	}
	var keyID peer.ID
	if has {
		// Turn key name into string representation of public key
		sk, err := i.keystore.Get(keyName)
		if err != nil {
			internalWebError(w, err)
			return
		}
		pk := sk.GetPublic()
		keyID, err = peer.IDFromPublicKey(pk)
		if err != nil {
			internalWebError(w, err)
			return
		}
	} else {
		// Generate key, then get string representation
		key, err := i.api.Key().Generate(r.Context(), keyName)
		if err != nil {
			internalWebError(w, err)
			return
		}
		keyID = key.ID()
	}

	keyEnc, err := ke.KeyEncoderFromString("base36") // Default encoding
	if err != nil {
		internalWebError(w, err)
		return
	}

	w.Header().Set("Location", "ipns://"+keyEnc.FormatID(keyID))
	w.WriteHeader(http.StatusCreated)
}

// ipnsPostHandler takes an /ipfs/ path in the body and updates the /ipns/ path in URL
func (i *gatewayHandler) ipnsPostHandler(w http.ResponseWriter, r *http.Request) {
	ipnsPath, keyFromPath, ok := decodeIpnsPath(w, r)
	if !ok {
		return
	}

	i.addUserHeaders(w)

	// Verify body is a valid /ipfs/ path

	buf, err := io.ReadAll(r.Body)
	if err != nil {
		webError(w, "WritableGateway: failed to read body", err, http.StatusBadRequest)
		return
	}
	bodyPath := string(buf)
	inCid, _, err := parseIpfsPath(bodyPath)
	if err != nil {
		webError(w, "WritableGateway: failed to parse the path", err, http.StatusBadRequest)
		return
	}

	start := time.Now()

	// Get current IPFS path and CID

	//

	// See if key is a key this node owns
	ourKey := false
	keyEnc, err := ke.KeyEncoderFromString("base36") // Default encoding
	if err != nil {
		internalWebError(w, err)
		return
	}
	keys, err := i.api.Key().List(r.Context())
	if err != nil {
		webError(w, "failed to retrieve list of keys", err, http.StatusInternalServerError)
		return
	}
	for _, key := range keys {
		if keyEnc.FormatID(key.ID()) == keyFromPath {
			ourKey = true
			break
		}
	}

	resolveCtx := r.Context()
	if ourKey {
		// Set resolution timeout because it should be very fast if there's anything to resolve
		// Because it's all local
		// Otherwise it will take a minute when there's nothing to resolve, looking on the DHT
		// and stuff. With this context it will give up early
		resolveCtx, _ = context.WithTimeout(r.Context(), 1*time.Second)
	}

	// Resolve current path for key
	var resolvedCid cid.Cid
	resolvedPath, err := i.api.Name().Resolve(resolveCtx, "/ipns/"+keyFromPath)
	golog.Println("name resolve time", time.Since(start))
	if err == nil {
		segs := strings.Split(resolvedPath.String(), "/")
		resolvedCid = cidMustDecode(segs[2])
	} else {
		// Path couldn't be resolved
		// This probably means that it doesn't exist
		// So create it, using the empty dir CID
		resolvedCid = emptyDirCid
	}

	var ipnsEntry coreiface.IpnsEntry
	var newCid cid.Cid

	if ipnsPath == "" {
		// Root is being replaced, so the provided /ipfs/ path can just be published

		start = time.Now()

		ipnsEntry, err = i.api.Name().Publish(
			r.Context(), ipath.New(bodyPath),
			options.Name.AllowOffline(true), options.Name.Key(keyFromPath),
		)
		if err != nil {
			webError(w, "WritableGateway: failed to publish path", err, http.StatusInternalServerError)
			return
		}

		golog.Println("name publish time", time.Since(start))

		newCid = inCid
	} else {
		// A subpath of the IPNS dir is being replaced

		// Add file/dir to path

		root, ok := i.rootFromCid(w, r, resolvedCid)
		if !ok {
			return
		}
		ok = i.addIpfsPathToDir(w, r, root, ipath.New(bodyPath), ipnsPath)
		if !ok {
			return
		}
		newCid, ok = i.finalizeDir(w, root)
		if !ok {
			return
		}

		// Publish new path

		ipnsEntry, err = i.api.Name().Publish(
			r.Context(), ipath.IpfsPath(newCid),
			options.Name.AllowOffline(true), options.Name.Key(keyFromPath),
		)
		if err != nil {
			webError(w, "WritableGateway: failed to publish path", err, http.StatusInternalServerError)
			return
		}
	}

	// Successfully published new path
	// Pin content and unpin old

	err = i.api.Pin().Add(r.Context(), ipath.IpfsPath(newCid))
	if err != nil {
		webError(w, "WritableGateway: name published but failed to pin new content", err,
			http.StatusInternalServerError)
		return
	}
	if !getV1(resolvedCid).Equals(emptyDirCid) {
		// There was something previously there to unpin
		err = i.api.Pin().Rm(r.Context(), ipath.IpfsPath(resolvedCid))
		if err != nil {
			webError(w, "WritableGateway: name published but failed to unpin new content", err,
				http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("X-IPNS-Path", gopath.Join("/ipns/", ipnsEntry.Name(), ipnsPath))
}

func (i *gatewayHandler) addUserHeaders(w http.ResponseWriter) {
	for k, v := range i.config.Headers {
		w.Header()[k] = v
	}
}

func webError(w http.ResponseWriter, message string, err error, defaultCode int) {
	if _, ok := err.(resolver.ErrNoLink); ok {
		webErrorWithCode(w, message, err, http.StatusNotFound)
	} else if err == routing.ErrNotFound {
		webErrorWithCode(w, message, err, http.StatusNotFound)
	} else if err == context.DeadlineExceeded {
		webErrorWithCode(w, message, err, http.StatusRequestTimeout)
	} else {
		webErrorWithCode(w, message, err, defaultCode)
	}
}

func webErrorWithCode(w http.ResponseWriter, message string, err error, code int) {
	http.Error(w, fmt.Sprintf("%s: %s", message, err), code)
	if code >= 500 {
		log.Warnf("server error: %s: %s", err)
	}
}

// return a 500 error and log
func internalWebError(w http.ResponseWriter, err error) {
	webErrorWithCode(w, "internalWebError", err, http.StatusInternalServerError)
}

func getFilename(s string) string {
	if (strings.HasPrefix(s, ipfsPathPrefix) || strings.HasPrefix(s, ipnsPathPrefix)) && strings.Count(gopath.Clean(s), "/") <= 2 {
		// Don't want to treat ipfs.io in /ipns/ipfs.io as a filename.
		return ""
	}
	return gopath.Base(s)
}

func (i *gatewayHandler) searchUpTreeFor404(r *http.Request, parsedPath ipath.Path) (ipath.Resolved, string, error) {
	filename404, ctype, err := preferred404Filename(r.Header.Values("Accept"))
	if err != nil {
		return nil, "", err
	}

	pathComponents := strings.Split(parsedPath.String(), "/")

	for idx := len(pathComponents); idx >= 3; idx-- {
		pretty404 := gopath.Join(append(pathComponents[0:idx], filename404)...)
		parsed404Path := ipath.New("/" + pretty404)
		if parsed404Path.IsValid() != nil {
			break
		}
		resolvedPath, err := i.api.ResolvePath(r.Context(), parsed404Path)
		if err != nil {
			continue
		}
		return resolvedPath, ctype, nil
	}

	return nil, "", fmt.Errorf("no pretty 404 in any parent folder")
}

func preferred404Filename(acceptHeaders []string) (string, string, error) {
	// If we ever want to offer a 404 file for a different content type
	// then this function will need to parse q weightings, but for now
	// the presence of anything matching HTML is enough.
	for _, acceptHeader := range acceptHeaders {
		accepted := strings.Split(acceptHeader, ",")
		for _, spec := range accepted {
			contentType := strings.SplitN(spec, ";", 1)[0]
			switch contentType {
			case "*/*", "text/*", "text/html":
				return "ipfs-404.html", "text/html", nil
			}
		}
	}

	return "", "", fmt.Errorf("there is no 404 file for the requested content types")
}

// Attempt to fix redundant /ipfs/ namespace as long as resulting
// 'intended' path is valid.  This is in case gremlins were tickled
// wrong way and user ended up at /ipfs/ipfs/{cid} or /ipfs/ipns/{id}
// like in bafybeien3m7mdn6imm425vc2s22erzyhbvk5n3ofzgikkhmdkh5cuqbpbq :^))
func fixupSuperfluousNamespace(w http.ResponseWriter, urlPath string, urlQuery string) bool {
	if !(strings.HasPrefix(urlPath, "/ipfs/ipfs/") || strings.HasPrefix(urlPath, "/ipfs/ipns/")) {
		return false // not a superfluous namespace
	}
	intendedPath := ipath.New(strings.TrimPrefix(urlPath, "/ipfs"))
	if err := intendedPath.IsValid(); err != nil {
		return false // not a valid path
	}
	intendedURL := intendedPath.String()
	if urlQuery != "" {
		// we render HTML, so ensure query entries are properly escaped
		q, _ := url.ParseQuery(urlQuery)
		intendedURL = intendedURL + "?" + q.Encode()
	}
	// return HTTP 400 (Bad Request) with HTML error page that:
	// - points at correct canonical path via <link> header
	// - displays human-readable error
	// - redirects to intendedURL after a short delay
	w.WriteHeader(http.StatusBadRequest)
	return redirectTemplate.Execute(w, redirectTemplateData{
		RedirectURL:   intendedURL,
		SuggestedPath: intendedPath.String(),
		ErrorMsg:      fmt.Sprintf("invalid path: %q should be %q", urlPath, intendedPath.String()),
	}) == nil
}

func cidMustDecode(s string) cid.Cid {
	c, err := cid.Decode(s)
	if err != nil {
		panic(err)
	}
	return c
}

// getV1 always returns a CIDv1
func getV1(c cid.Cid) cid.Cid {
	if c.Version() == 1 {
		return c
	}
	return cid.NewCidV1(c.Prefix().Codec, c.Hash())
}

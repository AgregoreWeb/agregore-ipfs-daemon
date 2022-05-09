# Agregore IPFS/IPNS Gateway Spec

## Table of Contents
- [Agregore IPFS/IPNS Gateway Spec](#agregore-ipfsipns-gateway-spec)
  - [Table of Contents](#table-of-contents)
  - [CORS](#cors)
  - [CIDs](#cids)
  - [Multipart Form Data](#multipart-form-data)
  - [IPFS APIs](#ipfs-apis)
    - [GET `/ipfs/<CID>[/<path>]`](#get-ipfscidpath)
      - [Path](#path)
      - [Headers](#headers)
      - [Query params](#query-params)
      - [Response](#response)
    - [HEAD `/ipfs/<CID>[/<path>]`](#head-ipfscidpath)
    - [POST `/ipfs/`](#post-ipfs)
      - [Headers](#headers-1)
      - [Response](#response-1)
    - [PUT `/ipfs/<CID>[/<path>]`](#put-ipfscidpath)
      - [Headers](#headers-2)
      - [Response](#response-2)
    - [DELETE `/ipfs/<CID>/<path>`](#delete-ipfscidpath)
      - [Headers](#headers-3)
      - [Response](#response-3)
    - [DELETE `/ipfs/<CID>`](#delete-ipfscid)
      - [Response](#response-4)
  - [IPNS APIs](#ipns-apis)
    - [GET or HEAD `/ipns/<key/domain>[/<path>]`](#get-or-head-ipnskeydomainpath)
      - [Options](#options)
      - [Response](#response-5)
    - [POST `/ipns/<key>[/<path>]`](#post-ipnskeypath)
      - [Request Body](#request-body)
      - [Response](#response-6)
    - [POST `/ipns/localhost[/<path>]`](#post-ipnslocalhostpath)
      - [Query params](#query-params-1)
      - [Response](#response-7)
    - [PUT `/ipns/<key>[/<path>]`](#put-ipnskeypath)
    - [PUT `/ipns/localhost[/<path>]`](#put-ipnslocalhostpath)
    - [DELETE `/ipns/<key>[/<path>]`](#delete-ipnskeypath)
      - [Response](#response-8)
    - [DELETE `/ipns/localhost[/<path>]`](#delete-ipnslocalhostpath)
      - [Query params](#query-params-2)
      - [Response](#response-9)
  - [Pubsub](#pubsub)
    - [GET `/pubsub/<topic>`](#get-pubsubtopic)
      - [Query params](#query-params-3)
      - [Response](#response-10)
    - [HEAD `/pubsub/<...>`](#head-pubsub)
    - [POST `/pubsub/<topic>`](#post-pubsubtopic)

## CORS

Responses always have the following headers to allow for cross-origin requests:

```
Access-Control-Allow-Headers: Content-Type
Access-Control-Allow-Headers: Range
Access-Control-Allow-Headers: User-Agent
Access-Control-Allow-Headers: X-Ipfs-Pin
Access-Control-Allow-Headers: X-Requested-With
Access-Control-Allow-Methods: GET
Access-Control-Allow-Methods: HEAD
Access-Control-Allow-Methods: POST
Access-Control-Allow-Methods: PUT
Access-Control-Allow-Methods: DELETE
Access-Control-Allow-Origin: *
Access-Control-Expose-Headers: Content-Range
Access-Control-Expose-Headers: Etag
Access-Control-Expose-Headers: Ipfs-Hash
Access-Control-Expose-Headers: X-Chunked-Output
Access-Control-Expose-Headers: X-Ipfs-Path
Access-Control-Expose-Headers: X-Ipns-Path
Access-Control-Expose-Headers: X-Stream-Output
Access-Control-Expose-Headers: X-Ipfs-Id
```

## CIDs

All CIDs returned from the API are CIDv1. CIDv0 are converted before being included in a response. This API will never output CIDv0. It accepts both in requests.

## Multipart Form Data

Some APIs support uploading multiple files in a single request using the `multipart/form-data` media type. The client must set `Content-Type: multipart/form-data`, and then set the request body to valid form data, as defined by [RFC 7578](https://datatracker.ietf.org/doc/html/rfc7578).

The name of the field containing the file data must be `file` to be uploaded. Fields with other names will be ignored. The filename desired for each file can be set in the filename part of the `Content-Disposition` header inside the form data.

Browser clients can use the [FormData](https://developer.mozilla.org/en-US/docs/Web/API/FormData) API to submit form data requests.


## IPFS APIs


### GET `/ipfs/<CID>[/<path>]`

Download IPFS data.

#### Path
- CID: IPFS CID, v0 and v1 supported
  - Ex: `QmfM2r8seH2GiRaC4esTjeraXEachRt8ZsSeGaWTPLyMoG` or `bafybeiczsscdsbs7ffqz55asqdf3smv6klcw3gofszvwlyarci47bgf354`
- path: path to files or directories under the CID if it's a directory
  - Ex: `/some/dir/file.txt`

#### Headers
- `Accept: application/json` return a JSON directory listing for directories

#### Query params
- `noResolve` return a directory listing for a directory even if it contains an `index.html` file
  - E: `/ipfs/.../my/dir?noResolve`
- `filename=some_filename` explicitly specify the filename
  - Ex: `https://ipfs.io/ipfs/QmfM2r8seH2GiRaC4esTjeraXEachRt8ZsSeGaWTPLyMoG?filename=hello_world.txt`
  - When you try to save above page, you browser will use passed `filename` instead of a CID.
- `download=true` skip browser rendering and trigger immediate "save as" dialog
  - Ex: `https://ipfs.io/ipfs/QmfM2r8seH2GiRaC4esTjeraXEachRt8ZsSeGaWTPLyMoG?filename=hello_world.txt&download=true`

#### Response
Serves the file at the provided path. If the path leads to a directory, the gateway behaves like a normal webserver, serving `index.html` or a directory listing as necessary - subject to the headers and query params listed above.

If the directory path does not end in a `/`, a `/` is appended and the user is redirected. This helps avoid serving duplicate content from different paths.

Etags and range requests are supported. File mimetypes are detected and set in `Content-Type`.

The header `X-IPFS-Path` is set to the URL path. `IPFS-Hash` is set to CID of the IPFS path provided, this may differ from the CID in the URL path.

### HEAD `/ipfs/<CID>[/<path>]`

The same as GET, but with no response body.

### POST `/ipfs/`

Upload file(s) to IPFS.

#### Headers
- `X-IPFS-Pin` pin the uploaded file(s) if this header is present

#### Response
The response body is uploaded, and a 201 Created redirect to `ipfs://<CID>` is returned. The response header `IPFS-Hash` is set to the CID of the uploaded content.

Form data is supported, in which case multiple files could be uploaded, and the returned CID would point to a directory containing those files.

### PUT `/ipfs/<CID>[/<path>]`

Upload a file to an existing path, such as `/ipfs/<CID>/path/to/file.ext`. Form data is supported, in which case the path must point to a directory, such as `/ipfs/<CID>/path/to/dir`.

This can also be used to wrap a file in a directory, by using the empty directory CID: `/ipfs/bafybeiczsscdsbs7ffqz55asqdf3smv6klcw3gofszvwlyarci47bgf354`.

#### Headers
- `X-IPFS-Pin` pin the resulting new CID if this header is present

#### Response
A 201 Created redirect to `ipfs://<new root CID>[/<path>]` is returned. The response header `IPFS-Hash` is set to the new root CID that has resulted from the
file(s) upload.

### DELETE `/ipfs/<CID>/<path>`

Remove the file or directory at the provided path.

#### Headers
- `X-IPFS-Pin` pin the new CID that results from deletion if this header is present

#### Response
A 201 Created redirect to `ipfs://<new root CID>[/<path>]` is returned. The path in the redirect is the directory containing the deletion path. So if the path in the URL was `/ipfs/<CID>/path/to/file.ext`, the redirect will be to `ipfs://<new CID>/path/to`.

The response header `IPFS-Hash` is set to the new root CID that has resulted from the deletion.

### DELETE `/ipfs/<CID>`

Unpin the provided CID.

#### Response
200 OK if successful.


## IPNS APIs


### GET or HEAD `/ipns/<key/domain>[/<path>]`

#### Options
Same as GET `/ipfs/<CID>[/<path>]`

#### Response
Resolves the IPNS key to an IPFS path, and then returns the same response as `/ipfs/`. Also supports resolving custom domains with [DNSLink](https://dnslink.io/).

The header `X-IPFS-Path` is set to the URL path. `IPFS-Hash` is set to CID of the IPFS path provided, this may differ from the CID in the URL path. This allows for getting the CID of an IPNS path/key.

### POST `/ipns/<key>[/<path>]`

Update all or part of the content behind an IPNS name. The new content is pinned, and the previous content is unpinned if it exists.

#### Request Body
A valid IPFS path in the format `/ipfs/<CID>[/<path>]` A naked CID is also valid.

#### Response
A 301 Temporary Redirect to `ipns://<key>[/<path>]`. The header `X-IPNS-Path` is set to the `/ipns/<key>[/<path>]`.

### POST `/ipns/localhost[/<path>]`

Behaves the same as `/ipns/<key>[/<path>]`.

#### Query params
- `key=some_name`: **Required**. This specifies the key you want by a name instead of by public key. If a key with this name doesn't exist, it will be created.

#### Response
The same as `/ipns/<key>[/<path>]`. Note this allows for extraction of the actual public key from future use and link sharing.

### PUT `/ipns/<key>[/<path>]`

The same as POST `/ipns/<key>[/<path>]`, but where the response body is the file to be uploaded, not an IPFS path. Multiple files can be uploaded using form data, in which case files will go inside the directory in the path.

### PUT `/ipns/localhost[/<path>]`

The same as POST `/ipns/localhost[/<path>]`, but where the response body is the file to be uploaded, not an IPFS path. Multiple files can be uploaded using form data, in which case files will go inside the directory in the path.

### DELETE `/ipns/<key>[/<path>]`

Remove content behind an IPNS name. The new content is pinned, and the previous content is unpinned.

#### Response
A 301 Temporary Redirect to `ipns://<key>[/<path>]`. The path in the redirect is the directory containing the deletion path. So if the path in the URL was `/ipns/<key>/path/to/file.ext`, the redirect will be to `ipns://<key>/path/to`.

The header `X-IPNS-Path` is set to `/ipns/<key>[/<path>]`, with the same path logic as above.

### DELETE `/ipns/localhost[/<path>]`

Behaves the same as `/ipns/<key>[/<path>]`.

#### Query params
- `key=some_name`: **Required**. This specifies the key you want by a name instead of by public key. If a key with this name doesn't exist, it will be created.

#### Response
The same as `/ipns/<key>[/<path>]`. Note this allows for extraction of the actual public key from future use and link sharing.

## Pubsub

An experimental pubsub API is supported to give users direct access to sending and receiving pubsub messages.

### GET `/pubsub/<topic>`

#### Query params
- `format`: can be `json`, `utf8`, `base64`, or not specified, which defaults to `base64`. This controls the decoding of pubsub message bytes

#### Response

The response is an [event stream](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events/Using_server-sent_events#event_stream_format), so pubsub messages for that topic will be sent to the client as long as the connection remains open.

Pubsub messages are encoded as events like this:

```
id: FuhB2orEIwE=
data: {"from":"QmfULfLaRtF7Kg3ShjFdiYL97P7eEcyL4PcvQLhkzCPCeG","data":"aGVsbG8=","topics":["test"]}
```

The "message identifier" of the pubsub message is base64-encoded to form the `id:`. `data:` is always encoded as JSON, with the other three things known about a pubsub message.

In the JSON: `from` is the prettified ID of the node who sent the message, `data` is the message data, and `topics` is an array of topics this message was sent to.

In the JSON, `data` is either a JSON object, a string, or bytes base64-encoded into a string. This behaviour depends on the format parameter mentioned above.

The response also contains the header `X-IPFS-ID` which is this node's prettified ID. This allows the client to filter out pubsub messages that come from itself.

Errors are also sent as events in the stream:

```
data: something failed blah blah
event: error
```

Errors with decoding the message bytes into the desired `format` are represented with the type `error-decode`:

```
event: error-decode
data: not valid UTF-8
```

### HEAD `/pubsub/<...>`

This will return the same headers as any GET pubsub request. The header that might be useful is `X-IPFS-ID`, described above.

This API call will work on `/pubsub/` and any path below it, and will always return the same headers.

### POST `/pubsub/<topic>`

Send a pubsub message, with a maximum size of 1 MiB. Anything larger is rejected with status code 413.

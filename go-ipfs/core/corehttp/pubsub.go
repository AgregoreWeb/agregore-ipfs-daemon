package corehttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/antage/eventsource"
	coreiface "github.com/ipfs/interface-go-ipfs-core"
)

// This file adds pubsub support to the gateway.
// It was created for Agregore Mobile.
// https://github.com/AgregoreWeb/agregore-ipfs-daemon/issues/5

const (
	// How long a pubsub SSE goroutine and pubsub topic listener goroutine stick
	// around after there are no more consumers
	pubsubDestructDelaySecs = 10
	// How long a pubsub message is waited on before giving up and doing other tasks
	// like checking consumer count
	pubsubMsgWaitTime = 60 * time.Second

	// libp2p docs indicate max msg size for pubsub is 1 MiB
	// https://github.com/libp2p/specs/issues/118
	maxPubsubMsgSize = 1 << 20
)

func (i *gatewayHandler) pubsubHeadHandler(w http.ResponseWriter, r *http.Request) {
	i.addUserHeaders(w)
	w.Header().Set("X-IPFS-ID", i.id.Pretty())
}

func (i *gatewayHandler) pubsubGetHandler(w http.ResponseWriter, r *http.Request) {
	topic := r.URL.Path[len("/pubsub/"):]
	if topic == "" {
		webError(w, "No topic specified", nil, http.StatusBadRequest)
		return
	}

	i.setupPubsubHeaders()

	format := strings.ToLower(r.URL.Query().Get("format"))
	if format == "" {
		format = "base64"
	} else if format != "json" && format != "utf8" && format != "base64" {
		webError(w, "unknown format param", nil, http.StatusBadRequest)
		return
	}

	es, err := i.getEventsource(r.Context(), topic, format)
	if err != nil {
		webError(w, "failed to subscribe to topic", err, http.StatusInternalServerError)
		return
	}

	// Hijack request to serve event stream
	es.ServeHTTP(w, r)
}

func (i *gatewayHandler) pubsubPostHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxPubsubMsgSize)

	topic := r.URL.Path[len("/pubsub/"):]
	if topic == "" {
		webError(w, "No topic specified", nil, http.StatusBadRequest)
		return
	}

	i.setupPubsubHeaders()

	var data bytes.Buffer
	_, err := io.Copy(&data, r.Body)
	if err != nil {
		if err.Error() == "http: request body too large" {
			webError(w, "max pubsub message size is 1 MiB", err, http.StatusRequestEntityTooLarge)
			return
		}
		webError(w, "failed to copy request data", err, http.StatusInternalServerError)
		return
	}

	err = i.api.PubSub().Publish(r.Context(), topic, data.Bytes())
	if err != nil {
		webError(w, "failed to publish data to topic", err, http.StatusInternalServerError)
		return
	}
}

// getEventSource gets an existing eventsource for the provided topic, or
// creates one as needed. Creation involves subscribing to the pubsub topic
// and starting a goroutine.
func (i *gatewayHandler) getEventsource(ctx context.Context, topic, format string) (eventsource.EventSource, error) {
	// Get eventsource or create if needed
	es, ok := i.eventsources[topic+"-"+format]
	if !ok {
		es = eventsource.New(
			nil,
			func(req *http.Request) [][]byte {
				return i.headerBytes
			},
		)

		pss, err := i.api.PubSub().Subscribe(ctx, topic)
		if err != nil {
			return nil, err
		}

		i.eventsources[topic+"-"+format] = es

		// Start goroutine that sends messages
		go i.pubsubMsgHandler(es, pss, topic, format)
	}
	return es, nil
}

func (i *gatewayHandler) setupPubsubHeaders() {
	// Convert custom headers to bytes for eventsource library
	if i.headerBytes == nil {
		i.headerBytes = make([][]byte, 0)
		for header, vals := range i.config.Headers {
			for j := range vals {
				i.headerBytes = append(i.headerBytes, []byte(fmt.Sprintf("%s: %s", header, vals[j])))
			}
		}
		// Add custom header providing the node's own ID, so pubsub messages from
		// itself can be filtered
		i.headerBytes = append(i.headerBytes, []byte("X-IPFS-ID: "+i.id.Pretty()))
	}

}

type pubSubMsg struct {
	From   string      `json:"from"`
	Data   interface{} `json:"data"`
	Topics []string    `json:"topics"`
}

func (i *gatewayHandler) pubsubMsgHandler(es eventsource.EventSource, pss coreiface.PubSubSubscription, topic, format string) {
	var timeSinceNoConsumers time.Time

	for {
		// Check on number of consumers to decide whether to release resources
		// and shut everything down

		if es.ConsumersCount() == 0 {
			if time.Since(timeSinceNoConsumers).Seconds() > pubsubDestructDelaySecs &&
				!timeSinceNoConsumers.IsZero() {
				// Time to shut everything down for this topic
				es.Close()
				pss.Close()
				delete(i.eventsources, topic+"-"+format)
				return
			} else if timeSinceNoConsumers.IsZero() {
				timeSinceNoConsumers = time.Now()
			}
		} else if !timeSinceNoConsumers.IsZero() {
			// The consumer count is higher than zero, but timeSinceNoConsumers has been set
			// So at one point the consumer count was zero, but now it's higher again
			// Reset timeSinceNoConsumers
			timeSinceNoConsumers = time.Time{}
		}

		// Check for message coming in

		ctx, cancel := context.WithTimeout(context.Background(), pubsubMsgWaitTime)
		msg, err := pss.Next(ctx)
		cancel()

		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			// Unexpected error
			es.SendEventMessage(err.Error(), "error", "")
		} else if err == nil {
			// Msg received
			psm := pubSubMsg{
				From:   string(msg.From().Pretty()),
				Topics: msg.Topics(),
			}

			switch format {
			case "json":
				err := json.Unmarshal(msg.Data(), &psm.Data)
				if err != nil {
					es.SendEventMessage(err.Error(), "error-decode", "")
					continue
				}
			case "utf8":
				if !utf8.Valid(msg.Data()) {
					es.SendEventMessage("not valid UTF-8", "error-decode", "")
					continue
				}
				psm.Data = string(msg.Data())
			default:
				// json.Marshal will base64-encode it
				psm.Data = msg.Data()
			}

			msgBytes, err := json.Marshal(&psm)
			if err != nil {
				es.SendEventMessage(err.Error(), "error", "")
			} else {
				// Seq, the "message identifier", is the ID, base64-encoded
				es.SendEventMessage(string(msgBytes), "", base64.StdEncoding.EncodeToString(msg.Seq()))
			}
		}
	}
}

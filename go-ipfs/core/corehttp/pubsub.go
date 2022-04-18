package corehttp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

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
	msgWaitTime = 60 * time.Second
)

func (i *gatewayHandler) pubsubGetHandler(w http.ResponseWriter, r *http.Request) {
	topic := r.URL.Path[len("/pubsub/"):]
	if topic == "" {
		webError(w, "No topic specified", nil, http.StatusBadRequest)
		return
	}

	// Convert custom headers to bytes for eventsource library
	if i.headerBytes == nil {
		headers := make([][]byte, 0)
		for header, vals := range i.config.Headers {
			for i := range vals {
				headers = append(headers, []byte(fmt.Sprintf("%s: %s", header, vals[i])))
			}
		}
	}

	// Get eventsource or create if needed
	es, ok := i.eventsources[topic]
	if !ok {
		es = eventsource.New(
			nil,
			func(req *http.Request) [][]byte {
				return i.headerBytes
			},
		)

		pss, err := i.api.PubSub().Subscribe(r.Context(), topic)
		if err != nil {
			webError(w, "failed to subscribe to topic", err, http.StatusInternalServerError)
			return
		}

		i.eventsources[topic] = es

		// Start goroutine that sends messages
		go i.pubsubMsgHandler(es, pss, topic)
	}

	// Hijack request to serve event stream
	es.ServeHTTP(w, r)
}

type pubSubMsg struct {
	From   string   `json:"from"`
	Data   []byte   `json:"data"`
	Topics []string `json:"topics"`
}

func (i *gatewayHandler) pubsubMsgHandler(es eventsource.EventSource, pss coreiface.PubSubSubscription, topic string) {
	var timeSinceNoConsumers time.Time

	for {
		ctx, cancel := context.WithTimeout(context.Background(), msgWaitTime)
		msg, err := pss.Next(ctx)
		cancel()

		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			// Unexpected error
			es.SendEventMessage(err.Error(), "error", "")
		} else if err != nil {
			// Msg received
			psm := pubSubMsg{
				From:   string(msg.From()),
				Data:   msg.Data(),
				Topics: msg.Topics(),
			}
			msgBytes, err := json.Marshal(&psm)
			if err != nil {
				es.SendEventMessage(err.Error(), "error", "")
			} else {
				// Seq, the "message identifier", is the ID, base64-encoded
				es.SendEventMessage(string(msgBytes), "", base64.StdEncoding.EncodeToString(msg.Seq()))
			}
		}

		// Check on number of consumers to decide whether to release resources
		// and shut everything down

		if es.ConsumersCount() == 0 {
			if time.Since(timeSinceNoConsumers).Seconds() > pubsubDestructDelaySecs &&
				!timeSinceNoConsumers.IsZero() {
				// Time to shut everything down for this topic
				es.Close()
				pss.Close()
				delete(i.eventsources, topic)
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
	}
}

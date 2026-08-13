package node

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
)

const signRecordSuffix = ".sign.record"

// principalOf asks the server who a connection is: the user-info reply
// carries the RESOLVED permission set, and the expanded scope template names
// the principal in its sign.record grant — server-asserted, never
// client-claimed. root is the identity plane's subject root (Config.root).
func principalOf(nc *nats.Conn, root string) (persona, account string, err error) {
	msg, err := nc.Request("$SYS.REQ.USER.INFO", nil, 5*time.Second)
	if err != nil {
		return "", "", fmt.Errorf("user info: %w", err)
	}
	var resp struct {
		Data struct {
			Permissions struct {
				Pub struct {
					Allow []string `json:"allow"`
				} `json:"publish"`
			} `json:"permissions"`
		} `json:"data"`
	}
	if err := json.Unmarshal(msg.Data, &resp); err != nil {
		return "", "", fmt.Errorf("user info decode: %w", err)
	}
	persona, account, ok := principalFromAllows(resp.Data.Permissions.Pub.Allow, root)
	if !ok {
		return "", "", fmt.Errorf("user info: no %s.<account>.<user>%s grant to derive the principal from — the deployment's scope template must carry it (allow=%v)", root, signRecordSuffix, resp.Data.Permissions.Pub.Allow)
	}
	return persona, account, nil
}

// principalFromAllows finds the one <root>.<account>.<persona>.sign.record
// grant in a resolved allow list. Pure; the parsing half of principalOf.
func principalFromAllows(allows []string, root string) (persona, account string, ok bool) {
	prefix := root + "."
	for _, subj := range allows {
		if !strings.HasPrefix(subj, prefix) || !strings.HasSuffix(subj, signRecordSuffix) {
			continue
		}
		middle := subj[len(prefix) : len(subj)-len(signRecordSuffix)]
		parts := strings.Split(middle, ".")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			continue
		}
		return parts[1], parts[0], true
	}
	return "", "", false
}

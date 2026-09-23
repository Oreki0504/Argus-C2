package identity

import (
	"encoding/json"

	"github.com/Oreki0504/Argus-C2/internal/localfile"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

func LoadNode(path string) (Node, error) {
	data, err := localfile.Read(path, 4096, false)
	if err != nil {
		return Node{}, err
	}
	return Decode(data)
}
func LoadRegistry(path string) (*Registry, error) {
	data, err := localfile.Read(path, 256*1024, false)
	if err != nil {
		return nil, err
	}
	var document struct {
		Agents []json.RawMessage `json:"agents"`
	}
	if err := strictjson.Decode(data, &document, 256*1024, "agents"); err != nil {
		return nil, err
	}
	records := make([]Registration, 0, len(document.Agents))
	for _, raw := range document.Agents {
		var record Registration
		if err := strictjson.Decode(raw, &record, 4096, "agent_id", "enrollment_epoch", "certificate_sha256", "enabled"); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return NewRegistry(records)
}

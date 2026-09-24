package protocol

import (
	"encoding/base64"
	"errors"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

const MaxEnrollmentBytes = 8192

type EnrollmentRequest struct {
	Version int    `json:"version"`
	Token   string `json:"token"`
	CSR     string `json:"csr_b64"`
}
type EnrollmentResponse struct {
	Version         int    `json:"version"`
	AgentID         string `json:"agent_id"`
	EnrollmentEpoch string `json:"enrollment_epoch"`
	CertificatePEM  string `json:"certificate_pem"`
}

func DecodeEnrollmentRequest(data []byte) (EnrollmentRequest, []byte, error) {
	var r EnrollmentRequest
	if err := strictjson.Decode(data, &r, MaxEnrollmentBytes, "version", "token", "csr_b64"); err != nil {
		return r, nil, err
	}
	csr, err := base64.RawURLEncoding.Strict().DecodeString(r.CSR)
	if err != nil || len(csr) == 0 || len(csr) > 2048 || base64.RawURLEncoding.EncodeToString(csr) != r.CSR || r.Version != Version || !identity.Hex(r.Token, 64) {
		return r, nil, errors.New("invalid enrollment request")
	}
	return r, csr, nil
}
func DecodeEnrollmentResponse(data []byte) (EnrollmentResponse, error) {
	var r EnrollmentResponse
	if err := strictjson.Decode(data, &r, MaxEnrollmentBytes, "version", "agent_id", "enrollment_epoch", "certificate_pem"); err != nil {
		return r, err
	}
	if r.Version != Version || (identity.Node{AgentID: r.AgentID, EnrollmentEpoch: r.EnrollmentEpoch}).Validate() != nil || len(r.CertificatePEM) == 0 || len(r.CertificatePEM) > 6000 {
		return r, errors.New("invalid enrollment response")
	}
	return r, nil
}

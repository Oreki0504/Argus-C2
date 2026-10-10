package protocol

import (
	"encoding/base64"
	"errors"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

const RenewalPath = "/api/v1/agent/certificate/renew"
const MaxRenewalBytes = 16384
const MaxCertificateGenerations = 64

type RenewalRequest struct {
	Version   int    `json:"version"`
	RenewalID string `json:"renewal_id"`
	CSR       string `json:"csr_b64"`
}

type RenewalResponse struct {
	Version            int    `json:"version"`
	RenewalID          string `json:"renewal_id"`
	AgentID            string `json:"agent_id"`
	Epoch              string `json:"enrollment_epoch"`
	Generation         int    `json:"generation"`
	PreviousSHA256     string `json:"previous_certificate_sha256"`
	PreviousValidUntil int64  `json:"previous_valid_until"`
	CertificatePEM     string `json:"certificate_pem"`
}

func DecodeRenewalRequest(data []byte) (RenewalRequest, []byte, error) {
	var r RenewalRequest
	if err := strictjson.Decode(data, &r, MaxRenewalBytes, "version", "renewal_id", "csr_b64"); err != nil {
		return r, nil, err
	}
	der, err := base64.RawURLEncoding.Strict().DecodeString(r.CSR)
	if err != nil || len(der) == 0 || len(der) > 2048 || base64.RawURLEncoding.EncodeToString(der) != r.CSR || r.Version != 1 || !identity.Hex(r.RenewalID, 32) {
		return r, nil, errors.New("invalid renewal request")
	}
	return r, der, nil
}

func DecodeRenewalResponse(data []byte) (RenewalResponse, error) {
	var r RenewalResponse
	if err := strictjson.Decode(data, &r, MaxRenewalBytes, "version", "renewal_id", "agent_id", "enrollment_epoch", "generation", "previous_certificate_sha256", "previous_valid_until", "certificate_pem"); err != nil {
		return r, err
	}
	if r.Version != 1 || !identity.Hex(r.RenewalID, 32) || (identity.Node{AgentID: r.AgentID, EnrollmentEpoch: r.Epoch}).Validate() != nil || r.Generation < 2 || r.Generation > MaxCertificateGenerations || !identity.Hex(r.PreviousSHA256, 64) || r.PreviousValidUntil <= 0 || len(r.CertificatePEM) == 0 || len(r.CertificatePEM) > 12000 {
		return r, errors.New("invalid renewal response")
	}
	return r, nil
}

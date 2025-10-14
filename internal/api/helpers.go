package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
)

// problemDetail is a struct for RFC 7807 "problem+json" responses.
type problemDetail struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
}

// respondWithError sends a JSON error response in the "problem+json" format.
// See: https://tools.ietf.org/html/rfc7807
func (s *Server) respondWithError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(problemDetail{
		Type:   "about:blank",
		Title:  http.StatusText(code),
		Status: code,
		Detail: message,
	}); err != nil {
		s.logger.Printf("Error encoding error response: %v", err)
	}
}

// respondWithJSON sends a JSON response.
func (s *Server) respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		s.logger.Printf("Error marshalling JSON response: %v", err)
		s.respondWithError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if _, err := w.Write(response); err != nil {
		s.logger.Printf("Error writing JSON response: %v", err)
	}
}

// getDirectoryPublicKey fetches a peer directory's public key from the server
// configuration.
func (s *Server) getDirectoryPublicKey(directoryURL string) (ed25519.PublicKey, error) {
	peer, ok := s.config.Peers[directoryURL]
	if !ok {
		return nil, fmt.Errorf("peer not found: %s", directoryURL)
	}
	pubKeyBytes, err := base64.RawURLEncoding.DecodeString(peer.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key for %s: %w", directoryURL, err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size for %s", directoryURL)
	}
	return ed25519.PublicKey(pubKeyBytes), nil
}

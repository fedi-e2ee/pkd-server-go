package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/fedi-e2ee/pkd-server-go/internal/protocol"
)

// protocolActionHandler defines the function signature for a protocol action handler.
type protocolActionHandler func(w http.ResponseWriter, r *http.Request, msg *protocol.ProtocolMessage)

// handleProtocolMessage is the main entry point for processing all protocol
// messages sent to the `/protocol` endpoint. It decodes the incoming message,
// validates the context, and routes the message to the appropriate handler
// based on the `action` field. It also handles HTTP Signature verification.
func (s *Server) handleProtocolMessage(w http.ResponseWriter, r *http.Request) {
	isActivityPub := strings.Contains(r.Header.Get("Content-Type"), "application/activity+json")

	// If it's an ActivityPub request, we need to read the body to check the action
	// and potentially verify the signature.
	if isActivityPub {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			var maxBytesError *http.MaxBytesError
			if errors.As(err, &maxBytesError) {
				s.respondWithError(w, http.StatusRequestEntityTooLarge, "Request body too large")
				return
			}
			s.respondWithError(w, http.StatusInternalServerError, "Failed to read request body")
			return
		}
		r.Body = io.NopCloser(bytes.NewBuffer(body))

		var msg preliminaryMessage
		if err := json.NewDecoder(bytes.NewReader(body)).Decode(&msg); err != nil {
			s.respondWithError(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}

		if msg.Action != "RevokeKeyThirdParty" {
			sigHeader := r.Header.Get("Signature")
			if sigHeader == "" {
				s.respondWithError(w, http.StatusUnauthorized, "Missing Signature header for ActivityPub request")
				return
			}

			params := parseSignatureHeader(sigHeader)
			keyID := params["keyId"]
			headers := params["headers"]
			signatureB64 := params["signature"]

			if keyID == "" || headers == "" || signatureB64 == "" {
				s.respondWithError(w, http.StatusBadRequest, "Invalid Signature header: missing keyId, headers, or signature")
				return
			}

			var signingString strings.Builder
			headerNames := strings.Fields(headers)
			for i, name := range headerNames {
				if i > 0 {
					signingString.WriteString("\n")
				}
				var value string
				if name == "(request-target)" {
					value = strings.ToLower(r.Method) + " " + r.URL.Path
				} else {
					value = r.Header.Get(name)
				}
				signingString.WriteString(strings.ToLower(name))
				signingString.WriteString(": ")
				signingString.WriteString(value)
			}

			pubKey, err := fetchActorPublicKey(keyID, s.config.Test.AllowPrivateIPs)
			if err != nil {
				s.logger.Printf("Failed to fetch public key for signature verification: %v", err)
				s.respondWithError(w, http.StatusForbidden, "Failed to fetch public key")
				return
			}
			ed25519PubKey, ok := pubKey.(ed25519.PublicKey)
			if !ok {
				s.respondWithError(w, http.StatusForbidden, "Public key is not an Ed25519 key")
				return
			}

			sigBytes, err := base64.StdEncoding.DecodeString(signatureB64)
			if err != nil {
				s.respondWithError(w, http.StatusBadRequest, "Invalid signature format: not valid base64")
				return
			}

			if !ed25519.Verify(ed25519PubKey, []byte(signingString.String()), sigBytes) {
				s.logger.Printf("HTTP Signature verification failed for keyId %s", keyID)
				s.respondWithError(w, http.StatusForbidden, "Invalid HTTP Signature")
				return
			}
			s.logger.Println("HTTP Signature verified successfully")
		}
	}

	// --- Original Message Processing Logic ---
	var fullMsg protocol.ProtocolMessage
	if err := json.NewDecoder(r.Body).Decode(&fullMsg); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			s.respondWithError(w, http.StatusRequestEntityTooLarge, "Request body too large")
			return
		}
		s.respondWithError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	if fullMsg.PKDContext != protocol.PKDContextV1 {
		s.respondWithError(w, http.StatusBadRequest, "Invalid !pkd-context")
		return
	}

	handler, ok := s.actionHandlers[fullMsg.Action]
	if !ok {
		s.respondWithError(w, http.StatusBadRequest, "Unsupported action: "+fullMsg.Action)
		return
	}

	handler(w, r, &fullMsg)
}

// preliminaryMessage is used to decode only the action from the request body
// to decide whether to perform signature verification before decoding the full message.
type preliminaryMessage struct {
	Action string `json:"action"`
}

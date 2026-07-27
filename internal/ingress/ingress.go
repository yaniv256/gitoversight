package ingress

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

var (
	ErrReplay       = errors.New("transaction already consumed")
	ErrSignature    = errors.New("signature invalid")
	ErrOversize     = errors.New("request body exceeds limit")
	ErrUnsolicited  = errors.New("approval tuple was not expected")
	ErrOAuthBinding = errors.New("oauth transaction binding mismatch")
	ErrExpired      = errors.New("transaction expired")
)

type ApprovalTuple struct {
	Nonce, Repository, Head, Manifest, Approver string
}

type GitHubReview struct {
	Repository string
	Head       string
	Approver   string
}

func VerifyGitHubReview(secret []byte, maxBody int, signature string, body []byte) (GitHubReview, error) {
	if err := VerifyGitHubSignature(secret, maxBody, signature, body); err != nil {
		return GitHubReview{}, err
	}
	var payload struct {
		Action     string `json:"action"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
		PullRequest struct {
			Head struct {
				SHA string `json:"sha"`
			} `json:"head"`
		} `json:"pull_request"`
		Review struct {
			State string `json:"state"`
			User  struct {
				Login string `json:"login"`
			} `json:"user"`
		} `json:"review"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || payload.Action != "submitted" || payload.Review.State != "approved" || payload.Repository.FullName == "" || payload.PullRequest.Head.SHA == "" || payload.Review.User.Login == "" {
		return GitHubReview{}, ErrUnsolicited
	}
	return GitHubReview{Repository: payload.Repository.FullName, Head: payload.PullRequest.Head.SHA, Approver: payload.Review.User.Login}, nil
}

func VerifyGitHubSignature(secret []byte, maxBody int, signature string, body []byte) error {
	if len(secret) < 32 || maxBody <= 0 || len(body) > maxBody {
		return ErrOversize
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(body)
	expectedSignature := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(signature), []byte(expectedSignature)) {
		return ErrSignature
	}
	return nil
}

type expectedApproval struct {
	tuple   ApprovalTuple
	expires time.Time
	used    bool
}

type WebhookVerifier struct {
	mu       sync.Mutex
	secret   []byte
	maxBody  int
	expected map[string]expectedApproval
}

func NewWebhookVerifier(secret []byte, maxBody int) *WebhookVerifier {
	return &WebhookVerifier{secret: append([]byte(nil), secret...), maxBody: maxBody, expected: make(map[string]expectedApproval)}
}

func (v *WebhookVerifier) Expect(tuple ApprovalTuple, expires time.Time) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if tuple.Nonce == "" || tuple.Repository == "" || tuple.Head == "" || tuple.Manifest == "" || tuple.Approver == "" || expires.IsZero() {
		return errors.New("approval tuple is incomplete")
	}
	if _, exists := v.expected[tuple.Nonce]; exists {
		return errors.New("approval nonce already exists")
	}
	v.expected[tuple.Nonce] = expectedApproval{tuple: tuple, expires: expires}
	return nil
}

func (v *WebhookVerifier) Consume(signature string, body []byte, now time.Time) error {
	_, err := v.ConsumeTuple(signature, body, now)
	return err
}

func (v *WebhookVerifier) ConsumeTuple(signature string, body []byte, now time.Time) (ApprovalTuple, error) {
	tuple, err := v.ResolveTuple(signature, body, now)
	if err != nil {
		return ApprovalTuple{}, err
	}
	if err := v.ConsumeExpected(tuple, now); err != nil {
		return ApprovalTuple{}, err
	}
	return tuple, nil
}

func (v *WebhookVerifier) ResolveTuple(signature string, body []byte, now time.Time) (ApprovalTuple, error) {
	if len(body) > v.maxBody {
		return ApprovalTuple{}, ErrOversize
	}
	mac := hmac.New(sha256.New, v.secret)
	mac.Write(body)
	expectedSignature := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(signature), []byte(expectedSignature)) {
		return ApprovalTuple{}, ErrSignature
	}
	var payload struct {
		Action       string `json:"action"`
		Nonce        string `json:"nonce"`
		ManifestHash string `json:"manifest_hash"`
		Repository   struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
		PullRequest struct {
			Head struct {
				SHA string `json:"sha"`
			} `json:"head"`
		} `json:"pull_request"`
		Review struct {
			State string `json:"state"`
			User  struct {
				Login string `json:"login"`
			} `json:"user"`
		} `json:"review"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || payload.Action != "submitted" || payload.Review.State != "approved" {
		return ApprovalTuple{}, ErrUnsolicited
	}
	tuple := ApprovalTuple{Nonce: payload.Nonce, Repository: payload.Repository.FullName, Head: payload.PullRequest.Head.SHA, Manifest: payload.ManifestHash, Approver: payload.Review.User.Login}
	v.mu.Lock()
	defer v.mu.Unlock()
	if tuple.Nonce == "" && tuple.Manifest == "" {
		var matched *expectedApproval
		for _, candidate := range v.expected {
			if candidate.tuple.Repository == tuple.Repository && candidate.tuple.Head == tuple.Head && candidate.tuple.Approver == tuple.Approver {
				if matched != nil {
					return ApprovalTuple{}, ErrUnsolicited
				}
				copy := candidate
				matched = &copy
			}
		}
		if matched == nil {
			return ApprovalTuple{}, ErrUnsolicited
		}
		tuple = matched.tuple
	}
	record, ok := v.expected[tuple.Nonce]
	if !ok || record.tuple != tuple {
		return ApprovalTuple{}, ErrUnsolicited
	}
	if record.used {
		return ApprovalTuple{}, ErrReplay
	}
	if !now.Before(record.expires) {
		return ApprovalTuple{}, ErrExpired
	}
	return tuple, nil
}

func (v *WebhookVerifier) ConsumeExpected(tuple ApprovalTuple, now time.Time) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	record, ok := v.expected[tuple.Nonce]
	if !ok || record.tuple != tuple {
		return ErrUnsolicited
	}
	if record.used {
		return ErrReplay
	}
	if !now.Before(record.expires) {
		return ErrExpired
	}
	record.used = true
	v.expected[tuple.Nonce] = record
	return nil
}

// Cancel removes an unused exact expectation. It is used only when the caller
// cannot durably record the expectation after registering it with the verifier.
func (v *WebhookVerifier) Cancel(tuple ApprovalTuple) {
	v.mu.Lock()
	defer v.mu.Unlock()
	record, ok := v.expected[tuple.Nonce]
	if ok && !record.used && record.tuple == tuple {
		delete(v.expected, tuple.Nonce)
	}
}

type OAuthTransaction struct {
	State, Session, Approver, RedirectURI, PKCEChallenge string
	Installation                                         int64
	ExpiresAt                                            time.Time
	used                                                 bool
}

type OAuthStore struct {
	mu           sync.Mutex
	transactions map[string]OAuthTransaction
}

func NewOAuthStore() *OAuthStore { return &OAuthStore{transactions: make(map[string]OAuthTransaction)} }

func (s *OAuthStore) Put(transaction OAuthTransaction) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if transaction.State == "" || transaction.Session == "" || transaction.Approver == "" || transaction.Installation == 0 || transaction.RedirectURI == "" || transaction.PKCEChallenge == "" || transaction.ExpiresAt.IsZero() {
		return errors.New("oauth transaction is incomplete")
	}
	if _, exists := s.transactions[transaction.State]; exists {
		return errors.New("oauth state already exists")
	}
	s.transactions[transaction.State] = transaction
	return nil
}

func (s *OAuthStore) Consume(state, session, approver string, installation int64, redirectURI, verifier string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	transaction, ok := s.transactions[state]
	if !ok {
		return ErrOAuthBinding
	}
	if transaction.used {
		return ErrReplay
	}
	if !now.Before(transaction.ExpiresAt) {
		return ErrExpired
	}
	if transaction.Session != session || transaction.Approver != approver || transaction.Installation != installation || transaction.RedirectURI != redirectURI || transaction.PKCEChallenge != PKCEChallenge(verifier) {
		return ErrOAuthBinding
	}
	transaction.used = true
	s.transactions[state] = transaction
	return nil
}

func PKCEChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

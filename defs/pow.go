package defs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/librespeed/speedtest-cli/output"
)

const (
	powChallengeFile = "pow.php"
	powVerifyFile    = "pow_verify.php"
	powMaxDifficulty = 24
	powGateBodyLimit = 256
)

var (
	powJarOnce sync.Once
	powSolved  sync.Map
	powLocks   sync.Map
)

var errPowUnsupported = fmt.Errorf("%s not published", powChallengeFile)

type powChallenge struct {
	Challenge  string `json:"challenge"`
	Difficulty int    `json:"difficulty"`
	Token      string `json:"token"`
}

type powVerdict struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func (s *Server) clearProofOfWork() error {
	start := time.Now()
	dir, err := s.powDir()
	if err != nil {
		return err
	}
	key := dir.String()
	if _, done := powSolved.Load(key); done {
		return nil
	}
	mu := powLock(key)
	mu.Lock()
	defer mu.Unlock()
	if _, done := powSolved.Load(key); done {
		return nil
	}
	enablePowCookieJar()
	primeSiteCookie(dir)
	challenge, err := fetchPowChallenge(dir)
	if err != nil {
		return err
	}
	nonce, err := solvePowChallenge(challenge.Challenge, challenge.Difficulty)
	if err != nil {
		return err
	}
	if err := submitPowSolution(dir, challenge, nonce); err != nil {
		return err
	}
	powSolved.Store(key, struct{}{})
	s.TLog.Logf("Proof of work took %s", time.Since(start).String())
	output.WriteDebug("Proof of work cleared for %s in %s\n",
		output.Sanitize(key), time.Since(start).Round(time.Millisecond))
	return nil
}

func powLock(key string) *sync.Mutex {
	if mu, ok := powLocks.Load(key); ok {
		return mu.(*sync.Mutex)
	}
	mu, _ := powLocks.LoadOrStore(key, &sync.Mutex{})
	return mu.(*sync.Mutex)
}

func enablePowCookieJar() {
	powJarOnce.Do(func() {
		if http.DefaultClient.Jar != nil {
			return
		}
		jar, err := cookiejar.New(nil)
		if err != nil {
			output.WriteDebug("Cannot create cookie jar: %s\n", err)
			return
		}
		http.DefaultClient.Jar = jar
	})
}

func gateBody(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	return len(trimmed) > 0 && len(trimmed) < powGateBodyLimit && !bytes.HasPrefix(trimmed, []byte("<"))
}

func (s *Server) powDir() (*url.URL, error) {
	base, err := s.GetURL()
	if err != nil {
		return nil, err
	}
	dir := path.Dir(s.PingURL)
	if dir == "." || dir == "/" {
		dir = ""
	}
	u := *base
	u.Path = path.Join(u.Path, dir)
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	u.RawQuery = ""
	u.Fragment = ""
	return &u, nil
}

func powEndpoint(dir *url.URL, file string) *url.URL {
	u := *dir
	u.Path = path.Join(u.Path, file)
	return &u
}

func primeSiteCookie(dir *url.URL) {
	root := *dir
	root.Path = "/"
	root.RawQuery = ""
	root.Fragment = ""
	req, err := http.NewRequest(http.MethodGet, root.String(), nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Cache-Control", "no-store")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		output.WriteDebug("Cannot fetch %s to prime the site cookie: %s\n",
			output.Sanitize(root.String()), err)
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
}

func fetchPowChallenge(dir *url.URL) (*powChallenge, error) {
	u := powEndpoint(dir, powChallengeFile)
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("User-Agent", UserAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, errPowUnsupported
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %s", powChallengeFile, resp.Status)
	}
	var challenge powChallenge
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&challenge); err != nil {
		return nil, fmt.Errorf("cannot parse %s response: %w", powChallengeFile, err)
	}
	switch {
	case challenge.Challenge == "":
		return nil, fmt.Errorf("%s returned an empty challenge", powChallengeFile)
	case challenge.Token == "":
		return nil, fmt.Errorf("%s returned an empty token", powChallengeFile)
	case challenge.Difficulty < 0:
		return nil, fmt.Errorf("%s returned an unusable difficulty: %d", powChallengeFile, challenge.Difficulty)
	case challenge.Difficulty > powMaxDifficulty:
		return nil, fmt.Errorf("%s asks for %d leading zero bits, above the %d this client will spend",
			powChallengeFile, challenge.Difficulty, powMaxDifficulty)
	}
	return &challenge, nil
}

func solvePowChallenge(challenge string, difficulty int) (string, error) {
	if difficulty <= 0 {
		return "0", nil
	}
	zeroes := (difficulty + 3) / 4
	target := strings.Repeat("0", zeroes)
	bytesToCheck := (zeroes + 1) / 2
	buf := make([]byte, len(challenge), len(challenge)+12)
	copy(buf, challenge)
	for nonce := 0; nonce < 1<<28; nonce++ {
		buf = strconv.AppendInt(buf[:len(challenge)], int64(nonce), 10)
		sum := sha256.Sum256(buf)
		if strings.HasPrefix(hex.EncodeToString(sum[:bytesToCheck]), target) {
			output.WriteDebug("Proof of work: nonce %d after %d attempt(s), difficulty %d\n",
				nonce, nonce+1, difficulty)
			return strconv.Itoa(nonce), nil
		}
	}
	return "", fmt.Errorf("no nonce found for difficulty %d within %d attempts", difficulty, 1<<28)
}

func submitPowSolution(dir *url.URL, challenge *powChallenge, nonce string) error {
	payload, err := json.Marshal(struct {
		Token string `json:"token"`
		Nonce string `json:"nonce"`
	}{Token: challenge.Token, Nonce: nonce})
	if err != nil {
		return err
	}
	u := powEndpoint(dir, powVerifyFile)
	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return err
	}
	var verdict powVerdict
	if err := json.Unmarshal(b, &verdict); err != nil {
		return fmt.Errorf("cannot parse %s response (HTTP %d): %q", powVerifyFile, resp.StatusCode, b)
	}
	if !verdict.Success {
		return fmt.Errorf("proof of work rejected (HTTP %d): %s",
			resp.StatusCode, output.Sanitize(verdict.Message))
	}
	return nil
}

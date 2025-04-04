package lib

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TecharoHQ/anubis"
	"github.com/TecharoHQ/anubis/internal"
	"github.com/TecharoHQ/anubis/lib/policy"
	"golang.org/x/net/html"
)

func loadPolicies(t *testing.T, fname string) *policy.ParsedConfig {
	t.Helper()

	loadedPolicies, err := LoadPoliciesOrDefault("", anubis.DefaultDifficulty)
	if err != nil {
		t.Fatal(err)
	}

	return loadedPolicies
}

func spawnAnubis(t *testing.T, opts Options) *Server {
	t.Helper()

	s, err := New(opts)
	if err != nil {
		t.Fatalf("can't construct libanubis.Server: %v", err)
	}

	return s
}

type challenge struct {
	Challenge string `json:"challenge"`
}

func makeChallenge(t *testing.T, ts *httptest.Server) challenge {
	t.Helper()

	resp, err := ts.Client().Post(ts.URL+"/.within.website/x/cmd/anubis/api/make-challenge", "", nil)
	if err != nil {
		t.Fatalf("can't request challenge: %v", err)
	}
	defer resp.Body.Close()

	var chall challenge
	if err := json.NewDecoder(resp.Body).Decode(&chall); err != nil {
		t.Fatalf("can't read challenge response body: %v", err)
	}

	return chall
}

// Regression test for CVE-2025-24369
func TestCVE2025_24369(t *testing.T) {
	pol := loadPolicies(t, "")
	pol.DefaultDifficulty = 4

	srv := spawnAnubis(t, Options{
		Next:   http.NewServeMux(),
		Policy: pol,

		CookieDomain:      "local.cetacean.club",
		CookiePartitioned: true,
		CookieName:        t.Name(),
	})

	ts := httptest.NewServer(internal.RemoteXRealIP(true, "tcp", srv))
	defer ts.Close()

	chall := makeChallenge(t, ts)
	calcString := fmt.Sprintf("%s%d", chall.Challenge, 0)
	calculated := internal.SHA256sum(calcString)
	nonce := 0
	elapsedTime := 420
	redir := "/"

	cli := ts.Client()
	cli.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/.within.website/x/cmd/anubis/api/pass-challenge", nil)
	if err != nil {
		t.Fatalf("can't make request: %v", err)
	}

	q := req.URL.Query()
	q.Set("response", calculated)
	q.Set("nonce", fmt.Sprint(nonce))
	q.Set("redir", redir)
	q.Set("elapsedTime", fmt.Sprint(elapsedTime))
	req.URL.RawQuery = q.Encode()

	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("can't do challenge passing")
	}

	if resp.StatusCode == http.StatusFound {
		t.Log("Regression on CVE-2025-24369")
		t.Errorf("wanted HTTP status %d, got: %d", http.StatusForbidden, resp.StatusCode)
	}
}

func TestCookieSettings(t *testing.T) {
	pol := loadPolicies(t, "")
	pol.DefaultDifficulty = 0

	srv := spawnAnubis(t, Options{
		Next:   http.NewServeMux(),
		Policy: pol,

		CookieDomain:      "local.cetacean.club",
		CookiePartitioned: true,
		CookieName:        t.Name(),
	})

	ts := httptest.NewServer(internal.RemoteXRealIP(true, "tcp", srv))
	defer ts.Close()

	cli := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := cli.Post(ts.URL+"/.within.website/x/cmd/anubis/api/make-challenge", "", nil)
	if err != nil {
		t.Fatalf("can't request challenge: %v", err)
	}
	defer resp.Body.Close()

	var chall = struct {
		Challenge string `json:"challenge"`
	}{}
	if err := json.NewDecoder(resp.Body).Decode(&chall); err != nil {
		t.Fatalf("can't read challenge response body: %v", err)
	}

	nonce := 0
	elapsedTime := 420
	redir := "/"
	calculated := ""
	calcString := fmt.Sprintf("%s%d", chall.Challenge, nonce)
	calculated = internal.SHA256sum(calcString)

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/.within.website/x/cmd/anubis/api/pass-challenge", nil)
	if err != nil {
		t.Fatalf("can't make request: %v", err)
	}

	q := req.URL.Query()
	q.Set("response", calculated)
	q.Set("nonce", fmt.Sprint(nonce))
	q.Set("redir", redir)
	q.Set("elapsedTime", fmt.Sprint(elapsedTime))
	req.URL.RawQuery = q.Encode()

	resp, err = cli.Do(req)
	if err != nil {
		t.Fatalf("can't do challenge passing")
	}

	if resp.StatusCode != http.StatusFound {
		t.Errorf("wanted %d, got: %d", http.StatusFound, resp.StatusCode)
	}

	var ckie *http.Cookie
	for _, cookie := range resp.Cookies() {
		t.Logf("%#v", cookie)
		if cookie.Name == anubis.CookieName {
			ckie = cookie
			break
		}
	}
	if ckie == nil {
		t.Errorf("Cookie %q not found", anubis.CookieName)
		return
	}

	if ckie.Domain != "local.cetacean.club" {
		t.Errorf("cookie domain is wrong, wanted local.cetacean.club, got: %s", ckie.Domain)
	}

	if ckie.Partitioned != srv.opts.CookiePartitioned {
		t.Errorf("wanted partitioned flag %v, got: %v", srv.opts.CookiePartitioned, ckie.Partitioned)
	}
}

func TestCheckDefaultDifficultyMatchesPolicy(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "OK")
	})

	for i := 1; i < 10; i++ {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			anubisPolicy, err := LoadPoliciesOrDefault("", i)
			if err != nil {
				t.Fatal(err)
			}

			s, err := New(Options{
				Next:           h,
				Policy:         anubisPolicy,
				ServeRobotsTXT: true,
			})
			if err != nil {
				t.Fatalf("can't construct libanubis.Server: %v", err)
			}

			req, err := http.NewRequest(http.MethodGet, "/", nil)
			if err != nil {
				t.Fatal(err)
			}

			req.Header.Add("X-Real-Ip", "127.0.0.1")

			_, bot, err := s.check(req)
			if err != nil {
				t.Fatal(err)
			}

			if bot.Challenge.Difficulty != i {
				t.Errorf("Challenge.Difficulty is wrong, wanted %d, got: %d", i, bot.Challenge.Difficulty)
			}

			if bot.Challenge.ReportAs != i {
				t.Errorf("Challenge.ReportAs is wrong, wanted %d, got: %d", i, bot.Challenge.ReportAs)
			}
		})
	}
}

func TestRenderIndexWithOGTitle(t *testing.T) {
	mockTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/og-title-only":
			w.Write([]byte(`<html><head><meta property="og:title" content="OG Title"></head><body>Hello</body></html>`))
		case "/html-title-only":
			w.Write([]byte(`<html><head><title>HTML Title</title></head><body>Hello</body></html>`))
		case "/both-titles":
			w.Write([]byte(`<html><head><title>HTML Title</title><meta property="og:title" content="OG Title"></head><body>Hello</body></html>`))
		case "/no-titles":
			w.Write([]byte(`<html><head><title>Making sure you're not a bot!</title></head><body>Hello</body></html>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockTarget.Close()

	pol := loadPolicies(t, "")

	anubisServer := spawnAnubis(t, Options{
		Next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("Unexpected call to Next handler for path: %s", r.URL.Path)
			http.Error(w, "Should not have reached Next handler in this test", http.StatusInternalServerError)
		}),
		Policy:          pol,
		OGPassthrough:   true,
		OGTimeToLive:    1 * time.Minute,
		OGQueryDistinct: false,
		Target:          mockTarget.URL,
	})

	testServer := httptest.NewServer(internal.RemoteXRealIP(true, "tcp", anubisServer))
	defer testServer.Close()

	// --- Test Cases ---
	testCases := []struct {
		name          string
		path          string
		expectedTitle string
	}{
		{"OG Title Only", "/og-title-only", "OG Title"},
		{"HTML Title Only", "/html-title-only", "HTML Title"},        // ogtags parser falls back to <title>
		{"Both Titles", "/both-titles", "HTML Title"},                // og:title meta tag takes precedence
		{"No Titles", "/no-titles", "Making sure you're not a bot!"}, // Default title
		{"Not Found", "/not-found", "Making sure you're not a bot!"}, // Default title on error fetching OG tags
	}

	// Use a single client for all tests
	client := testServer.Client()
	// Prevent the client from following redirects automatically if Anubis were to issue one
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	for _, tc := range testCases {
		tc := tc // Capture range variable
		t.Run(tc.name, func(t *testing.T) {
			// --- Execute Request ---
			req, err := http.NewRequest("GET", testServer.URL+tc.path, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			// Add realistic headers often checked by WAFs/policies
			// X-Real-Ip is added by the RemoteXRealIP middleware in testServer
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Failed to perform request: %v", err)
			}
			defer resp.Body.Close()

			// Expect 200 OK because Anubis should render the challenge page
			if resp.StatusCode != http.StatusOK {
				bodyBytes, _ := io.ReadAll(resp.Body) // Read body for debugging info
				t.Logf("Response Headers: %v", resp.Header)
				t.Logf("Response Body: %s", string(bodyBytes))
				t.Fatalf("Expected status OK (200), got %d for path %s", resp.StatusCode, tc.path)
			}

			// --- Verify HTML Title ---
			doc, err := html.Parse(resp.Body)
			if err != nil {
				t.Fatalf("Failed to parse response HTML: %v", err)
			}

			actualTitle := ""
			var crawler func(*html.Node)
			crawler = func(node *html.Node) {
				// Stop crawling if title already found
				if actualTitle != "" {
					return
				}
				if node.Type == html.ElementNode && node.Data == "title" {
					if node.FirstChild != nil && node.FirstChild.Type == html.TextNode {
						actualTitle = strings.TrimSpace(node.FirstChild.Data)
						return // Found it
					}
				}
				for c := node.FirstChild; c != nil; c = c.NextSibling {
					crawler(c)
					// Optimization: if crawler found it in a child, stop iterating siblings
					if actualTitle != "" {
						return
					}
				}
			}
			crawler(doc)

			if actualTitle == "" && tc.expectedTitle != "Making sure you're not a bot!" {
				// If we expected a specific title but found none in the HTML
				t.Errorf("Expected title '%s', but no <title> tag was found in the response", tc.expectedTitle)
			} else if actualTitle != "" && actualTitle != tc.expectedTitle {
				// If we found a title but it doesn't match
				t.Errorf("Expected title '%s', but got '%s'", tc.expectedTitle, actualTitle)
			} else if actualTitle == "" && tc.expectedTitle == "Making sure you're not a bot!" {
				// If we correctly expected the default title (because none was found in HTML) - This is OK
				t.Logf("Correctly got default title because no <title> tag was found.")
			}
		})
	}
}

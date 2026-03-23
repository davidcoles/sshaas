package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
)

const HEADER = "X-SSH-as-a-Service"

type User struct {
	Name       string   `json:"name"`
	Key        string   `json:"key"`
	CA         string   `json:"ca"`
	Principals []string `json:"principals"`
}

type Config struct {
	CA    map[string]string `json:"ca"`
	Users []User            `json:"users"`
}

var DEFAULTCA = "default"
var ENDPOINT = "http://localhost:9999/sshaas"
var LIFETIME = flag.Uint("lifetime", 5, "certificate lifetime (minutes)")

func main() {

	endpoint := flag.String("endpoint", ENDPOINT, "endpoint url")
	config := flag.String("config", "", "config file for server mode")
	listen := flag.String("listen", "127.0.0.1:9999", "address to listen on")

	flag.Parse()
	args := flag.Args()

	conn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))

	if err != nil {
		log.Fatalf("Failed to open SSH_AUTH_SOCK: %v", err)
	}

	client := agent.NewClient(conn)

	if *config != "" {
		server(client, *listen, *config, args...)
		return
	}

	var identifier string

	if len(args) > 0 {
		identifier = args[0]
	}

	list, err := client.List()

	if err != nil {
		log.Fatal(err)
	}

	// first look for a key that matches the identifier given on the command line, if present
	if identifier != "" {
		for _, key := range list {
			blob := base64.StdEncoding.EncodeToString(key.Marshal())
			if key.Comment == identifier || blob == identifier {
				authWithKey(client, key, *endpoint)
				return
			}
		}
	}

	// failing that look for the first ssh-ed25519 key
	for _, key := range list {
		if key.Format == "ssh-ed25519" {
			authWithKey(client, key, *endpoint)
			return
		}
	}

	// failing that try the first key available
	for _, key := range list {
		authWithKey(client, key, *endpoint)
		return
	}

	log.Fatal("No suitable key found")
}

func server(client agent.Agent, listen, configFile string, keys ...string) {

	var config Config

	conf := loadFile(configFile)

	err := json.Unmarshal(conf, &config)

	if err != nil {
		log.Fatal(err)
	}

	for _, k := range keys {

		raw := loadFile(k)
		privateKey, err := ssh.ParseRawPrivateKey(raw)

		if _, ok := err.(*ssh.PassphraseMissingError); ok {

			var passphrase []byte

			fmt.Printf("%s passphrase: ")

			passphrase, err = terminal.ReadPassword(int(syscall.Stdin))

			if err != nil {
				log.Fatal(err)
			}

			privateKey, err = ssh.ParseRawPrivateKeyWithPassphrase(raw, passphrase)
		}

		if err != nil {
			log.Fatal(err)
		}

		addedKey := agent.AddedKey{
			PrivateKey: privateKey,
			Comment:    k,
		}

		// add the key/cert to ssh-agent
		err = client.Add(addedKey)

		if err != nil {
			log.Fatal(err)
		}
	}

	users := make(map[string]User)

	for _, u := range config.Users {
		users[u.Key] = u
	}

	http.HandleFunc("/sshaas", func(w http.ResponseWriter, r *http.Request) {

		var signer ssh.Signer

		var b body

		// obtain the token from the http headers and validate that is correctly signed
		token := r.Header.Get(HEADER)
		supplicant, err := b.decode(token)

		if err != nil {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, err)
			return
		}

		// look up the signing key in the user database
		user, exists := users[supplicant]

		if !exists {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, "Unknown key")
			return
		}

		if len(user.Principals) < 1 {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, "No principals listed")
			return
		}

		ca := user.CA

		if ca == "" {
			ca = DEFAULTCA
		}

		pub, exists := config.CA[ca]

		if !exists {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, "CA not found")
			return
		}

		list, _ := client.Signers()

		for _, s := range list {
			key := s.PublicKey()
			blob := base64.StdEncoding.EncodeToString(key.Marshal())
			//log.Println(key, blob)
			if pub == blob {
				// this is the key that we're looking for
				signer = s
			}
		}

		if signer == nil {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, "signing key not found:", pub)
			return
		}

		// unmarshal the ephemeral public key
		raw, err := base64.StdEncoding.DecodeString(b.EphemeralKey)

		if err != nil {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, err)
			return
		}

		key, err := ssh.ParsePublicKey(raw)

		if err != nil {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, err)
			return
		}

		now := uint64(time.Now().Unix())

		permissions := map[string]string{
			//"permit-X11-forwarding":   "",
			//"permit-agent-forwarding": "",
			//"permit-port-forwarding": "",
			"permit-pty": "",
			//"permit-user-rc":          "",
		}

		// create a certificate for the ephemeral key with the principals from the user database
		cert := ssh.Certificate{
			Key:             key,
			Serial:          uint64(time.Now().UnixNano()), // this could likely be better done
			CertType:        ssh.UserCert,
			KeyId:           fmt.Sprint(now),
			ValidPrincipals: user.Principals,
			ValidAfter:      now - 30, // allow for a little clock skew (seconds)
			ValidBefore:     now + uint64(*LIFETIME*60),
			Permissions:     ssh.Permissions{Extensions: permissions},
			//Nonce          []byte
			//Reserved       []byte
			//SignatureKey   PublicKey
			//Signature      *Signature
		}

		// sign the certificate with the CA private key
		if err = cert.SignCert(rand.Reader, signer); err != nil {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, err)
			return
		}

		// return to the client!
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		w.Write(cert.Marshal())
		return
	})

	fmt.Println("Listening ...")
	log.Fatal(http.ListenAndServe(listen, nil))
}

func authWithKey(client agent.Agent, authKey *agent.Key, endpoint string) {

	// generate an ephemeral key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)

	if err != nil {
		log.Fatal(err)
	}

	// obtain an ssh representation for submitting to the server
	sshPublicKey, err := ssh.NewPublicKey(publicKey)

	if err != nil {
		log.Fatal(err)
	}

	// marshal it into the base64 representaion
	b := body{
		EphemeralKey: base64.StdEncoding.EncodeToString(sshPublicKey.Marshal()),
	}

	// sign the request with the auth key picked from ssh-agent
	tokenString, err := b.encode(client, authKey)

	if err != nil {
		log.Fatal(err)
	}

	// submit the token to the server and hope that our request is approved
	certificate, err := getCertificate(endpoint, tokenString)

	if err != nil {
		log.Fatal(err)
	}

	now := uint64(time.Now().Unix())

	// prepare a request to the ssh-agent, specifying our ephemeral private key and its certificate
	addedKey := agent.AddedKey{
		PrivateKey:   privateKey,
		Certificate:  certificate,
		Comment:      "SSH-as-a-Service",
		LifetimeSecs: uint32(certificate.ValidBefore - now),
		//ConfirmBeforeUse bool
		//ConstraintExtensions []ConstraintExtension
	}

	// add the key/cert to ssh-agent
	err = client.Add(addedKey)

	if err != nil {
		log.Fatal(err)
	}

	expires := time.Unix(int64(certificate.ValidBefore), 0)

	fmt.Println("certificate expires:", expires)
}

func getCertificate(endpoint, token string) (*ssh.Certificate, error) {

	client := &http.Client{}
	req, err := http.NewRequest("GET", endpoint, nil)

	if err != nil {
		return nil, err
	}

	req.Header.Set(HEADER, token)

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)

	if err != nil {
		return nil, err
	}

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("Status: %d: %s", res.StatusCode, string(body))
	}

	pk, err := ssh.ParsePublicKey(body)

	if err != nil {
		return nil, err
	}

	cert, ok := pk.(*ssh.Certificate)

	if !ok {
		return nil, fmt.Errorf("Not a certificate")
	}

	return cert, nil

}

func loadFile(file string) []byte {

	if file == "" {
		return nil
	}

	f, err := os.Open(file)

	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()

	b, err := ioutil.ReadAll(f)

	if err != nil {
		log.Fatal(err)
	}

	return b
}

// JWT-like structures for generating/vaildating  a token
type body struct {
	EphemeralKey string `json:"key"`
}

type head struct {
	Format string `json:"fmt"`
	Key    string `json:"key"`
}

func (h *head) marshal() (string, error) { return marshal(h) }
func (b *body) marshal() (string, error) { return marshal(b) }
func (h *head) unmarshal(s string) error { return unmarshal(s, h) }
func (b *body) unmarshal(s string) error { return unmarshal(s, b) }

func marshal(a any) (string, error) {
	js, err := json.Marshal(a)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(js), nil
}

func unmarshal(s string, a any) (err error) {
	var b []byte

	if b, err = base64.RawURLEncoding.DecodeString(s); err != nil {
		return
	}

	return json.Unmarshal(b, a)
}

func (b *body) encode(client agent.Agent, key *agent.Key) (s string, err error) {

	var header, payload string
	var signature *ssh.Signature

	// prepare the header with the key and its type
	h := head{Format: key.Format, Key: base64.StdEncoding.EncodeToString(key.Marshal())}

	if payload, err = b.marshal(); err != nil {
		return
	}

	if header, err = h.marshal(); err != nil {
		return
	}

	preamble := header + "." + payload

	// sign the base64 encoded head and body
	if signature, err = client.Sign(key, []byte(preamble)); err != nil {
		return
	}

	// concatenate the signature onto the base64 encoded head and body
	return preamble + "." + base64.RawURLEncoding.EncodeToString(signature.Blob), nil
}

func (b *body) decode(token string) (string, error) {

	m := strings.SplitN(token, ".", 3)

	if len(m) != 3 {
		return "", fmt.Errorf("Bad token")
	}

	var h head

	if err := h.unmarshal(m[0]); err != nil {
		return "", err
	}

	// take the key from the header ...
	pub, err := base64.StdEncoding.DecodeString(h.Key)

	if err != nil {
		return "", err
	}

	key, err := ssh.ParsePublicKey(pub)

	if err != nil {
		return "", err
	}

	// ... and the signature
	blob, err := base64.RawURLEncoding.DecodeString(m[2])

	if err != nil {
		return "", err
	}

	signature := ssh.Signature{
		Format: h.Format,
		Blob:   blob,
	}

	// verify that the key specified in the header signed the header and body and nothing was tampered with
	if err = key.Verify([]byte(m[0]+"."+m[1]), &signature); err != nil {
		return "", err
	}

	// now that the token has been verified we can unmarshal the body
	if err = b.unmarshal(m[1]); err != nil {
		return "", err
	}

	return h.Key, nil
}

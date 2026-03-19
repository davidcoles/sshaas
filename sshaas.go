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
	Principals []string `json:"principals"`
}

type Config struct {
	Users []User `json:"users"`
}

var ENDPOINT = flag.String("endpoint", "http://localhost:9999/sshaas", "endpoint url")
var LIFETIME = flag.Uint("lifetime", 300, "certificate lifetime (seconds)")

func main() {

	keyFile := flag.String("key", "", "ssh private key file")
	listen := flag.String("listen", "127.0.0.1:9999", "address to listen on")

	flag.Parse()
	args := flag.Args()

	if *keyFile == "" {
		client(args)
		return
	}

	configFile := args[0]

	conf := loadFile(configFile)
	key := loadFile(*keyFile)

	var config Config

	err := json.Unmarshal(conf, &config)

	if err != nil {
		log.Fatal(err)
	}

	var passphrase []byte

	privateKey, err := ssh.ParseRawPrivateKey(key)

	if _, ok := err.(*ssh.PassphraseMissingError); ok {

		fmt.Println("Passphrase:")

		passphrase, err = terminal.ReadPassword(int(syscall.Stdin))

		if err != nil {
			log.Fatal(err)
		}

		privateKey, err = ssh.ParseRawPrivateKeyWithPassphrase(key, passphrase)
	}

	if err != nil {
		log.Fatal(err)
	}

	signer, err := ssh.NewSignerFromKey(privateKey)

	if err != nil {
		log.Fatal(err)
	}

	keys := make(map[string][]string)

	for _, u := range config.Users {
		keys[u.Key] = u.Principals
	}

	http.HandleFunc("/sshaas", func(w http.ResponseWriter, r *http.Request) {

		var b body

		token := r.Header.Get(HEADER)
		supplicant, err := b.decode(token)

		if err != nil {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, err)
			return
		}

		principals, exists := keys[supplicant]

		if !exists {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, "Unknown key")
			return
		}

		raw, err := base64.StdEncoding.DecodeString(b.Key)

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

		cert := ssh.Certificate{
			Key:             key,
			Serial:          uint64(time.Now().UnixNano()), // this could likely be better done
			CertType:        ssh.UserCert,
			KeyId:           fmt.Sprint(now),
			ValidPrincipals: principals,
			ValidAfter:      now - 30, // allow for a little clock skew
			ValidBefore:     now + uint64(*LIFETIME),
			Permissions:     ssh.Permissions{Extensions: permissions},
			//Nonce          []byte
			//Reserved       []byte
			//SignatureKey   PublicKey
			//Signature      *Signature
		}

		if err = cert.SignCert(rand.Reader, signer); err != nil {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, err)
			return
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		w.Write(cert.Marshal())
		return
	})

	fmt.Println("Listening ...")
	log.Fatal(http.ListenAndServe(*listen, nil))
}

func client(args []string) {

	var marker string

	if len(args) > 0 {
		marker = args[0]
	}

	conn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))

	if err != nil {
		log.Fatalf("Failed to open SSH_AUTH_SOCK: %v", err)
	}

	client := agent.NewClient(conn)

	list, err := client.List()

	if err != nil {
		log.Fatal(err)
	}

	if marker != "" {
		for _, key := range list {
			blob := base64.RawURLEncoding.EncodeToString(key.Marshal())
			if key.Comment == marker || blob == marker {
				authWithKey(client, key)
				return
			}
		}
	}

	for _, key := range list {
		if key.Format == "ssh-ed25519" {
			authWithKey(client, key)
			return
		}
	}

	for _, key := range list {
		authWithKey(client, key)
		return
	}

	log.Fatal("No suitable key found")
}

func authWithKey(client agent.Agent, k *agent.Key) {

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)

	if err != nil {
		log.Fatal(err)
	}

	sshPublicKey, err := ssh.NewPublicKey(publicKey)

	if err != nil {
		log.Fatal(err)
	}

	b := body{
		Key: base64.StdEncoding.EncodeToString(sshPublicKey.Marshal()),
	}

	tokenString, err := b.encode(client, k)

	if err != nil {
		log.Fatal(err)
	}

	certificate, err := getCertificate(tokenString)

	if err != nil {
		log.Fatal(err)
	}

	now := uint64(time.Now().Unix())

	addedKey := agent.AddedKey{
		PrivateKey:   privateKey,
		Certificate:  certificate,
		Comment:      "SSH-as-a-Service",
		LifetimeSecs: uint32(certificate.ValidBefore - now),
		//ConfirmBeforeUse bool
		//ConstraintExtensions []ConstraintExtension
	}

	err = client.Add(addedKey)

	if err != nil {
		log.Fatal(err)
	}
}

func getCertificate(token string) (*ssh.Certificate, error) {

	client := &http.Client{}
	req, err := http.NewRequest("GET", *ENDPOINT, nil)

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

type body struct {
	Key string `json:"key"`
}

type head struct {
	Fmt string `json:"fmt"`
	Key string `json:"key"`
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

	h := head{Fmt: key.Format, Key: base64.StdEncoding.EncodeToString(key.Marshal())}

	var header, payload string
	var signature *ssh.Signature

	if payload, err = b.marshal(); err != nil {
		return
	}

	if header, err = h.marshal(); err != nil {
		return
	}

	preamble := header + "." + payload

	if signature, err = client.Sign(key, []byte(preamble)); err != nil {
		return
	}

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

	pub, err := base64.StdEncoding.DecodeString(h.Key)

	if err != nil {
		return "", err
	}

	key, err := ssh.ParsePublicKey(pub)

	if err != nil {
		return "", err
	}

	blob, err := base64.RawURLEncoding.DecodeString(m[2])

	if err != nil {
		return "", err
	}

	var signature ssh.Signature

	signature.Format = h.Fmt
	signature.Blob = blob

	if err = key.Verify([]byte(m[0]+"."+m[1]), &signature); err != nil {
		return "", err
	}

	if err = b.unmarshal(m[1]); err != nil {
		return "", err
	}

	return h.Key, nil
}

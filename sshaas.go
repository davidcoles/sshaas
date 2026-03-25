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
const COMMENT = "SSH-as-a-Service"

type User struct {
	Id         string   `json:"id"`
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
	remove := flag.Bool("remove", false, "remove certs/keys")

	flag.Parse()
	args := flag.Args()

	conn, err := dial()

	if err != nil {
		log.Fatalf("Failed to open ssh-agent connection: %v", err)
	}

	client := agent.NewClient(conn)

	if *config != "" {
		server(client, *listen, *config, args...)
		return
	}

	fmt.Println("Agent contacted")

	var identifier string

	if len(args) > 0 {
		identifier = args[0]
	}

	list, err := client.List()

	if err != nil {
		log.Fatal(err)
	}

	if *remove {
		for _, key := range list {
			if key.Comment == COMMENT {
				client.Remove(key)
			}
		}
		return
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

		var token Token

		// obtain the token from the http headers and validate that is correctly signed
		supplicant, err := token.decode(r.Header.Get(HEADER))

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

		signers, _ := client.Signers()

		for _, s := range signers {
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
		raw, err := base64.StdEncoding.DecodeString(token.EphemeralKey)

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

		keyId := user.Key

		if user.Id != "" {
			keyId = user.Id
		}

		// create a certificate for the ephemeral key with the principals from the user database
		cert := ssh.Certificate{
			Key:             key,
			Serial:          uint64(time.Now().UnixNano()), // this could likely be better done
			CertType:        ssh.UserCert,
			KeyId:           keyId, //fmt.Sprint(now),
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
	token := Token{
		Format:       authKey.Format,
		Supplicant:   base64.StdEncoding.EncodeToString(authKey.Marshal()),
		EphemeralKey: base64.StdEncoding.EncodeToString(sshPublicKey.Marshal()),
	}

	// sign the request with the auth key picked from ssh-agent
	tokenString, err := token.encode(client, authKey)

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
		Comment:      COMMENT,
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

type Token struct {
	Format       string `json:"format"`
	Supplicant   string `json:"supplicant"`
	EphemeralKey string `json:"key"`
}

func (t *Token) encode(client agent.Agent, key *agent.Key) (s string, err error) {

	t.Format = key.Format
	t.Supplicant = base64.StdEncoding.EncodeToString(key.Marshal())

	js, err := json.Marshal(t)

	if err != nil {
		return
	}

	payload := base64.RawURLEncoding.EncodeToString(js)

	signature, err := client.Sign(key, []byte(payload))

	if err != nil {
		return
	}

	return payload + "." + base64.RawURLEncoding.EncodeToString(signature.Blob), nil
}

func (t *Token) decode(s string) (string, error) {

	m := strings.SplitN(s, ".", 2)

	if len(m) != 2 {
		return "", fmt.Errorf("Bad token")
	}

	js, err := base64.RawURLEncoding.DecodeString(m[0])

	if err != nil {
		return "", err
	}

	err = json.Unmarshal(js, t)

	if err != nil {
		return "", err
	}

	pub, err := base64.StdEncoding.DecodeString(t.Supplicant)

	if err != nil {
		return "", err
	}

	key, err := ssh.ParsePublicKey(pub)

	if err != nil {
		return "", err
	}

	blob, err := base64.RawURLEncoding.DecodeString(m[1])

	if err != nil {
		return "", err
	}

	signature := ssh.Signature{
		Format: t.Format,
		Blob:   blob,
	}

	// verify that the key specified in the token was used to sign it
	if err = key.Verify([]byte(m[0]), &signature); err != nil {
		return "", err
	}

	return t.Supplicant, nil
}

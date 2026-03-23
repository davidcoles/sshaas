
DOMAIN ?= default
ENDPOINT ?= http://localhost:9999/sshaas

all: sshaas config.json

sshaas:
	go build -ldflags "-X main.ENDPOINT=$(ENDPOINT) -X main.DOMAIN=$(DOMAIN)"

config.json:
	yq -o json . config.yaml > config.tmp
	mv config.tmp config.json

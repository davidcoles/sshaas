
all: sshaas config.json

sshaas:
	go build

config.json:
	yq -o json . config.yaml > config.tmp
	mv config.tmp config.json

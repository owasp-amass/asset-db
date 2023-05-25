.PHONY: test

include .env.local

export $(shell sed 's/=.*//' .env.local)

test:
	go test -v ./...

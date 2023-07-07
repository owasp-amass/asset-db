.PHONY: test

include .env.local

export $(shell sed 's/=.*//' .env.local)

test:
	go test -count=1 -v -cover ./...

SHELL=/bin/bash
.PHONY: dummyplaceholder


help:	# Show this help text
	@cat Makefile | grep -e '^[a-zA-Z]*:'

buildall:
	dub build --config=app-no-tls
	dub build --config=app
	dub build --config=app-ssl3
	dub build --config=lib-no-tls
	dub build --config=lib
	dub build --config=lib-ssl3

buildallforce:
	dub build --force --config=app-no-tls
	dub build --force --config=app
	dub build --force --config=app-ssl3
	dub build --force --config=lib-no-tls
	dub build --force --config=lib
	dub build --force --config=lib-ssl3
	
testall:
	dub test --config=app-no-tls
	dub test --config=app
	dub test --config=app-ssl3
	dub test --config=lib-no-tls
	dub test --config=lib
	dub test --config=lib-ssl3

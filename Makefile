
.PHONY: tests deps deps-python deps-javascript deps-rust \
        test-erlang test-python test-javascript test-ruby test-rust test-go test-c test-java clean

tests: deps test-erlang test-python test-javascript test-ruby test-rust test-go test-c test-java

deps: deps-python deps-javascript deps-rust

deps-python:
	pip3 install -q --root-user-action=ignore -r python/requirements.txt

deps-javascript:
	cd javascript && bun install

deps-rust:
	cd rust && cargo fetch

test-erlang:
	@echo "=== Erlang ==="
	cd erlang && erlc pki.erl test_pki.erl && erl -noshell -eval "code:load_abs(filename:absname(\"pki\")), eunit:test(test_pki, [verbose]), init:stop()."

test-python:
	@echo "=== Python ==="
	cd python && python3 test_pki.py

test-javascript:
	@echo "=== JavaScript ==="
	cd javascript && bun test_pki.js

test-ruby:
	@echo "=== Ruby ==="
	cd ruby && ruby test_pki.rb

test-rust:
	@echo "=== Rust ==="
	cd rust && cargo test --tests 2>&1

test-go:
	@echo "=== Go ==="
	cd go && go test -v .

test-c:
	@echo "=== C ==="
	cd c && make test

test-java:
	@echo "=== Java ==="
	cd java && make test

clean:
	rm -f erlang/*.beam
	rm -rf rust/target
	rm -rf javascript/node_modules
	cd c && make clean
	cd java && make clean
	find . -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null; true
	find . -name '*.pyc' -delete 2>/dev/null; true
	rm -f fixtures/sig_*.json fixtures/test_*.json

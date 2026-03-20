
.PHONY: tests test-erlang test-python test-javascript test-ruby test-rust test-go clean

tests: test-erlang test-python test-javascript test-ruby test-rust test-go

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

clean:
	rm -f erlang/*.beam

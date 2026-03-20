
.PHONY: tests test-erlang test-python test-javascript test-ruby test-rust clean

tests: test-erlang test-python test-javascript test-ruby test-rust

test-erlang:
	@echo "=== Erlang ==="
	erlc pki.erl test/test_pki.erl
	erl -noshell -eval "code:load_abs(filename:absname(\"pki\")), eunit:test(test_pki, [verbose]), init:stop()."

test-python:
	@echo "=== Python ==="
	python3 test/test_pki.py

test-javascript:
	@echo "=== JavaScript ==="
	bun test/test_pki.js

test-ruby:
	@echo "=== Ruby ==="
	ruby test/test_pki.rb

test-rust:
	@echo "=== Rust ==="
	cargo test --tests 2>&1

clean:
	rm -f *.beam test/*.beam

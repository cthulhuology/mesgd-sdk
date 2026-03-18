
.PHONY: test test-erlang test-python test-javascript test-ruby clean

test: test-erlang test-python test-javascript test-ruby

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

clean:
	rm -f *.beam test/*.beam

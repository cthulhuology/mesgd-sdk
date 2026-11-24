
.PHONY: tests deps deps-python deps-javascript deps-rust deps-dart \
        test-erlang test-python test-javascript test-ruby test-rust test-go test-c test-java test-csharp test-dart \
        test-mesgd test-mesgd-erlang test-mesgd-python test-mesgd-javascript \
        test-mesgd-go test-mesgd-ruby test-mesgd-rust test-mesgd-c test-mesgd-dart clean

tests: deps test-dart test-erlang test-python test-javascript test-ruby test-rust test-go test-c test-java test-csharp test-mesgd
	$(MAKE) test-dart

deps: deps-python deps-javascript deps-rust deps-dart

deps-python:
	pip3 install -q --root-user-action=ignore -r python/requirements.txt

deps-javascript:
	cd javascript && bun install

deps-rust:
	cd rust && cargo fetch

deps-dart:
	cd dart && dart pub get

test-erlang:
	@echo "=== Erlang ==="
	cd erlang && erlc pki.erl test_pki.erl && erl -noshell -pa $(HOME)/.beamer -eval "code:load_abs(filename:absname(\"pki\")), eunit:test(test_pki, [verbose]), init:stop()."

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

test-csharp:
	@echo "=== C# ==="
	cd csharp && make test

test-dart: deps-dart
	@echo "=== Dart ==="
	cd dart && dart test

test-mesgd: test-mesgd-erlang test-mesgd-python test-mesgd-javascript \
            test-mesgd-go test-mesgd-ruby test-mesgd-rust test-mesgd-c test-mesgd-dart

test-mesgd-erlang:
	@echo "=== Erlang mesgd protocol ==="
	cd erlang && erlc pki.erl test_mesgd.erl && erl -noshell -pa $(HOME)/.beamer -eval "code:load_abs(filename:absname(\"pki\")), eunit:test(test_mesgd, [verbose]), init:stop()."

test-mesgd-python:
	@echo "=== Python mesgd protocol ==="
	cd python && python3 test_mesgd.py

test-mesgd-javascript:
	@echo "=== JavaScript mesgd protocol ==="
	cd javascript && node test_mesgd.js

test-mesgd-go:
	@echo "=== Go mesgd protocol ==="
	cd go && go test -v -run 'TestTwoParty|TestSigned|TestCompact|TestLive'

test-mesgd-ruby:
	@echo "=== Ruby mesgd protocol ==="
	cd ruby && ruby test_mesgd.rb

test-mesgd-rust:
	@echo "=== Rust mesgd protocol ==="
	cd rust && cargo test --test test_mesgd -- --nocapture

test-mesgd-c:
	@echo "=== C mesgd protocol ==="
	cd c && make test-mesgd

test-mesgd-dart: deps-dart
	@echo "=== Dart mesgd protocol ==="
	cd dart && dart test test/mesgd_test.dart test/mesgd_ws_test.dart

clean:
	rm -f erlang/*.beam
	rm -rf rust/target
	rm -rf javascript/node_modules
	cd c && make clean
	cd java && make clean
	cd csharp && make clean
	rm -rf dart/.dart_tool
	find . -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null; true
	find . -name '*.pyc' -delete 2>/dev/null; true
	rm -f fixtures/sig_*.json fixtures/test_*.json fixtures/ct_*.json

# Password + authenticator auth clients (no dependency downloads).
.PHONY: test-auth test-auth-live
tests: test-auth

test-auth:
	python3 tests/test_auth.py

test-auth-live:
	python3 tests/test_auth_live.py

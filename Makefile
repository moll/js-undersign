NODE = node
NODE_OPTS = --use-strict
MOCHA = ./node_modules/.bin/_mocha
TEST = test/**/*_test.js

love:
	@echo "Feel like makin' love."

test:
	@$(NODE) $(NODE_OPTS) $(MOCHA) -R dot $(TEST)

spec:
	@$(NODE) $(NODE_OPTS) $(MOCHA) -R spec $(TEST)

autotest:
	@$(NODE) $(NODE_OPTS) $(MOCHA) -R dot --watch $(TEST)

autospec:
	@$(NODE) $(NODE_OPTS) $(MOCHA) -R spec --watch $(TEST)

shrinkwrap:
	npm shrinkwrap --dev

pack:
	@file=$$(npm pack); echo "$$file"; tar tf "$$file"

publish:
	npm publish

tag:
	git tag "v$$($(NODE) -e 'console.log(require("./package").version)')"

clean:
	-$(RM) *.tgz
	npm prune --production

tsl: tsl/eu.xml
tsl: tsl/ee.xml
tsl: tsl/ee_test.xml

tsl/eu.xml:
	mkdir -p tsl
	wget "https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml" -O "$@"

tsl/ee.xml:
	mkdir -p tsl
	wget "https://sr.riik.ee/tsl/estonian-tsl.xml" -O "$@"

tsl/ee_test.xml:
	mkdir -p tsl
	wget "https://open-eid.github.io/test-TL/EE_T.xml" -O "$@"

test/fixtures/rsa.key:
	openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$@"

test/fixtures/rsa.pub: test/fixtures/rsa.key
	openssl rsa -pubout -in "$<" -out "$@"

test/fixtures/ecdsa.key:
	openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$@"

test/fixtures/ecdsa.pub: test/fixtures/ecdsa.key
	openssl ec -in "$<" -pubout -out "$@"

.PHONY: love
.PHONY: test spec autotest autospec
.PHONY: shrinkwrap
.PHONY: pack publish tag
.PHONY: clean
.PHONY: tsl

.PRECIOUS: test/fixtures/rsa.key
.PRECIOUS: test/fixtures/ecdsa.key

JAVA    = /usr/lib64/jdk23-23.0.2/bin/java
KOTLINC = /mnt/d/kotlin/bin/kotlinc
JAVALIB = ../java/lib
CP      = $(JAVALIB)/json.jar:$(JAVALIB)/junit-standalone.jar
JUNIT   = $(JAVALIB)/junit-standalone.jar

.PHONY: all test clean

all: pki_test.jar

pki_test.jar: pki.kt test_pki.kt
	$(KOTLINC) -cp $(CP) -include-runtime pki.kt test_pki.kt -d pki_test.jar 2>&1

test: pki_test.jar
	$(JAVA) -jar $(JUNIT) --select-class=PKITest --classpath=pki_test.jar:$(CP) --details=verbose 2>&1

clean:
	rm -f pki_test.jar

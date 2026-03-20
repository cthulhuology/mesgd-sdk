JAVA    = /usr/lib64/jdk23-23.0.2/bin/java
JAVAC   = /usr/lib64/jdk23-23.0.2/bin/javac
CP      = lib/json.jar:lib/junit-standalone.jar
JUNIT   = lib/junit-standalone.jar

.PHONY: all test clean

all: PKI.class

PKI.class: pki.java PKITest.java
	$(JAVAC) -cp $(CP) pki.java PKITest.java

test: PKI.class
	$(JAVA) -jar $(JUNIT) --select-class=PKITest --classpath=.:$(CP) --details=verbose 2>&1

clean:
	rm -f *.class

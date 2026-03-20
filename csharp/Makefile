DOTNET = /root/.dotnet/dotnet

.PHONY: all test publish clean

all: test

test:
	$(DOTNET) run --project csharp.csproj

publish:
	$(DOTNET) publish csharp.csproj -r linux-x64 --self-contained true \
	    -p:PublishSingleFile=true -p:PublishTrimmed=false \
	    -o publish/ --nologo -v quiet

clean:
	rm -rf bin/ obj/ publish/

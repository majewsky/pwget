default: build/pwget

GOPATH := # unset (to force people to use golangvend)

build/pwget: main.go
	go build -o $@ $<

install: build/pwget
	install -D -m 0755 build/pwget "$(DESTDIR)/usr/bin/pwget"

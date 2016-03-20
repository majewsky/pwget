default: build/pwget

GOPATH := # unset (to force people to use golangvend)

build/pwget: main.go
	go build -o $@ $<

install: build/pwget README.md
	install -D -m 0755 build/pwget "$(DESTDIR)/usr/bin/pwget"
	install -D -m 0644 README.md   "$(DESTDIR)/usr/share/doc/pwget/README.md"

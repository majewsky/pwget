PKG = github.com/majewsky/pwget
PREFIX=/usr

all: build/pwget

GO            = GOPATH=$(CURDIR)/.gopath GOBIN=$(CURDIR)/build go
GO_BUILDFLAGS =
GO_LDFLAGS    = -s -w

build/pwget: main.go
	$(GO) install $(GO_BUILDFLAGS) -ldflags '$(GO_LDFLAGS)' '$(PKG)'

install: FORCE all
	install -D -m 0755 build/pwget "$(DESTDIR)$(PREFIX)/bin/pwget2"
	install -D -m 0644 README.md   "$(DESTDIR)$(PREFIX)/share/doc/pwget2/README.md"

# vendoring by https://github.com/holocm/golangvend
vendor: FORCE
	@golangvend

.PHONY: FORCE

default: build/pwget

GOPATH := # unset (to force people to use golangvend)

build/pwget: main.go
	go build -o $@ $<

# ktls

Experimental Linux kernel TLS support for Go. Upstream Go isn't particularly keen on adding kTLS [#44506](https://github.com/golang/go/issues/44506) as they are skeptical of it's performance benefits and the loss of control over the TLS stack. However this dismisses a very important use case for kTLS, hardware offload. If you can bypass userspace with sendfile and splice and you have a NIC that supports HW crypto, kTLS is an absolute game changer.

Right now it's very loosely integrated into the Go TLS stack, but it's a start and I'm using it to implement [tlshd-go](https://github.com/dpeckett/tlshd-go).

## Usage

Replace all uses of `crypto/tls` with `github.com/dpeckett/ktls/tls`, and once you complete the tls handshake you can call `ktls.Enable(conn)` to enable kTLS.

Implementing TLS alert handling etc is left as an exercise for the reader.
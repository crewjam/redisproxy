package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

// randomPort returns an available TCP port.
func randomPort() uint16 {
	l, _ := net.Listen("tcp", ":0")
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	return uint16(port)
}

func TestIntegration(t *testing.T) {
	serverPort := randomPort()
	listenPort := randomPort()

	tmpDir, err := ioutil.TempDir("", "redisproxy-test")
	if err != nil {
		t.Error(err)
		return
	}
	defer os.RemoveAll(tmpDir)

	ioutil.WriteFile(filepath.Join(tmpDir, "config.yaml"),
		[]byte(`
groups:
  - name: frontend
    ou: ["frontend"]
  - name: web
    ou: ["web"]
rules:
  - groups: ["frontend"]
    commands: [["^PING$"]]
`), 0600)

	ioutil.WriteFile(filepath.Join(tmpDir, "key.pem"),
		[]byte(serverKey), 0600)
	ioutil.WriteFile(filepath.Join(tmpDir, "cert.pem"),
		[]byte(serverCert), 0600)
	ioutil.WriteFile(filepath.Join(tmpDir, "ca.pem"),
		[]byte(rootCert), 0600)

	// start redis
	ioutil.WriteFile(filepath.Join(tmpDir, "redis.conf"), []byte(fmt.Sprintf(`
appendfsync everysec
appendonly no
bind 127.0.0.1
daemonize no
databases 16
dbfilename dump.rdb
dir %s
no-appendfsync-on-rewrite no
port %d
rdbcompression yes
save 300 10
save 60 10000
save 900 1
slave-serve-stale-data yes
slowlog-log-slower-than 10000
slowlog-max-len 1024
timeout 0`, tmpDir, serverPort)), 0600)

	log.WithField("phase", "start_redis").Info()
	cmd := exec.Command("redis-server", filepath.Join(tmpDir, "redis.conf"))
	if err := cmd.Start(); err != nil {
		t.Error(err)
		return
	}
	defer func() {
		log.WithField("phase", "stop_redis").Info()
		cmd.Process.Kill()
	}()

	os.Args = []string{"redisproxy",
		"-config", filepath.Join(tmpDir, "config.yaml"),
		"-cert", filepath.Join(tmpDir, "cert.pem"),
		"-key", filepath.Join(tmpDir, "key.pem"),
		"-client-ca", filepath.Join(tmpDir, "ca.pem"),
		"-listen", fmt.Sprintf("localhost:%d", listenPort),
		"-server", fmt.Sprintf("localhost:%d", serverPort),
	}
	log.WithField("phase", "invoke_main").WithField("args", os.Args).Info()

	mainErrCh := make(chan error, 1)
	go func() {
		err := Main()
		if err != nil {
			log.WithError(err).Error("main exited")
		}
		mainErrCh <- err
	}()

	// Give time for the server to start.
	// TODO(ross): something less moronic than sleep
	time.Sleep(time.Second)

	// connect and see which commands we can actually use
	{
		clientKeyPair, _ := tls.X509KeyPair([]byte(clientCert), []byte(clientKey))
		rootCAs := x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM([]byte(rootCert)) {
			t.Errorf("cannot parse client CA")
			return
		}

		tlsConfig := tls.Config{
			Certificates: []tls.Certificate{clientKeyPair},
			RootCAs:      rootCAs,
		}

		conn, err := tls.Dial("tcp", fmt.Sprintf("localhost:%d", listenPort), &tlsConfig)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()

		// send a ping -- should get a PONG back
		{
			_, err = fmt.Fprintf(conn, "*1\r\n$4\r\nPING\r\n")
			if err != nil {
				t.Error(err)
				return
			}

			buf := make([]byte, 7)
			_, err = conn.Read(buf)
			if err != nil {
				t.Error(err)
				return
			}
			if string(buf) != "+PONG\r\n" {
				t.Errorf("expected \"+PONG\\r\\n\" got %q", string(buf))
			}
		}

		// send an LLEN - should get ACCESS DENIED
		{
			_, err = fmt.Fprintf(conn, "*2\r\n$4\r\nLLEN\r\n$6\r\nmylist\r\n")
			if err != nil {
				t.Error(err)
				return
			}

			buf := make([]byte, 16)
			_, err = conn.Read(buf)
			if err != nil {
				t.Error(err)
				return
			}
			if string(buf) != "-ACCESS DENIED\r\n" {
				t.Errorf("expected ACCESS DENIED got %q", string(buf))
			}
		}
	}

	// connect with a different cert (the server cert, as it happens) which
	// does not have access, and note that PING returns ACCESS DENIED.
	{
		clientKeyPair, _ := tls.X509KeyPair([]byte(serverCert), []byte(serverKey))
		rootCAs := x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM([]byte(rootCert)) {
			t.Errorf("cannot parse client CA")
			return
		}
		tlsConfig := tls.Config{
			Certificates: []tls.Certificate{clientKeyPair},
			RootCAs:      rootCAs,
		}
		conn, err := tls.Dial("tcp", fmt.Sprintf("localhost:%d", listenPort), &tlsConfig)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()

		{
			_, err = fmt.Fprintf(conn, "*1\r\n$4\r\nPING\r\n")
			if err != nil {
				t.Error(err)
				return
			}

			buf := make([]byte, 16)
			_, err = conn.Read(buf)
			if err != nil {
				t.Error(err)
				return
			}
			if string(buf) != "-ACCESS DENIED\r\n" {
				t.Errorf("expected ACCESS DENIED got %q", string(buf))
			}
		}
	}

	// send ourselves SIGINT
	thisProc, _ := os.FindProcess(os.Getpid())
	thisProc.Signal(os.Interrupt)

	err = <-mainErrCh
	if err != nil {
		t.Error(err)
		return
	}
}

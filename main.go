package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"

	log "github.com/sirupsen/logrus"

	"gopkg.in/yaml.v2"

	redisproxy "github.com/crewjam/redisproxy/lib"
)

func main() {
	if err := Main(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func Main() error {
	configPath := flag.String("config", "", "The path to the config file")
	listen := flag.String("listen", ":6380", "The address to listen on")
	server := flag.String("server", "localhost:6379", "The address of the redis server")
	certPath := flag.String("cert", "", "The path to the TLS certificate")
	keyPath := flag.String("key", "", "The path to the TLS key")
	clientCAPath := flag.String("client-ca", "", "The path to the client CA certificate")
	flag.Parse()

	// read the configuration
	configBuf, err := ioutil.ReadFile(*configPath)
	if err != nil {
		return fmt.Errorf("cannot read config file: %s", err)
	}
	config := struct {
		Groups []redisproxy.Group `yaml:"groups"`
		Rules  []redisproxy.Rule  `yaml:"rules"`
	}{}
	if err := yaml.Unmarshal(configBuf, &config); err != nil {
		return fmt.Errorf("cannot parse config file: %s", err)
	}

	// read the SSL settings
	certificate, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		return fmt.Errorf("cannot read certificates: %s", err)
	}
	clientCAs := x509.NewCertPool()
	clientCAbuf, err := ioutil.ReadFile(*clientCAPath)
	if err != nil {
		return fmt.Errorf("cannot read client CA: %s", err)
	}
	if !clientCAs.AppendCertsFromPEM(clientCAbuf) {
		return fmt.Errorf("cannot parse client CA")
	}

	// listen
	listener, err := tls.Listen("tcp", *listen,
		&tls.Config{
			Certificates: []tls.Certificate{certificate},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clientCAs,
		})
	if err != nil {
		return err
	}
	log.WithField("address", *listen).Info("listening")

	p := redisproxy.RedisProxy{
		Listener:      listener,
		ServerAddress: *server,
		Rules:         config.Rules,
		Groups:        config.Groups,
	}

	errCh := make(chan error)
	go func() {
		errCh <- p.Run()
	}()

	doneCh := make(chan os.Signal)
	signal.Notify(doneCh, os.Interrupt, os.Kill)
	<-doneCh
	log.WithField("address", *listen).Info("received shutdown signal")

	listener.Close()

	return <-errCh
}

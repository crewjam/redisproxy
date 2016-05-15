package redisproxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"regexp"

	log "github.com/sirupsen/logrus"
)

// Group represents a remote user. Connections are assigned
// to one or more groups based on the OrganizationUnit (OU)
// of the valid TLS client certificate presented.
type Group struct {
	Name                string   `yaml:"name"`
	OrganizationalUnits []string `yaml:"ou"`
}

// Rule represents an allowed command. The command is allowed
// for the specified groups. Each allowed command is a list of
// regular expressions. For a command to match a rule the
// command must match each of the regular expressions.
type Rule struct {
	Groups   []string   `yaml:"groups"`
	Commands [][]string `yaml:"commands"`
}

// AppliesToGroup returns true if this rule applies to the
// specified group
func (r Rule) AppliesToGroup(group Group) bool {
	for _, groupName := range r.Groups {
		if groupName == group.Name {
			return true
		}
	}
	return false
}

// Matches returns true if the specified command matches
// any of the regular expressions.
func (r Rule) Matches(command [][]byte) bool {
	for _, cmd := range r.Commands {
		if len(cmd) != len(command) {
			continue
		}
		for i := range cmd {
			cmdRe := regexp.MustCompile(cmd[i])
			if cmdRe.Match(command[i]) {
				return true
			}
		}
	}
	return false
}

// RedisProxy is a server that proxies connections to a Redis
// server authorizing users according to the specified
// Groups and Rules.
type RedisProxy struct {
	Listener      net.Listener
	ServerAddress string
	Groups        []Group
	Rules         []Rule
}

// Run is the main proxy run loop. It accepts connections and
// invokes HandleConnection with each accepted connection.
func (rp *RedisProxy) Run() error {
	for {
		conn, err := rp.Listener.Accept()
		if err != nil {
			return err
		}
		go rp.HandleConnection(conn)
	}
}

// HandleConnection is invoked with each connection. It checks that
// the connection is authorized, and if so, it proxies traffic. Data
// from the client are passed to the server via FilterConnection.
func (rp *RedisProxy) HandleConnection(clientConn net.Conn) error {
	logEntry := log.WithField("remote", clientConn.RemoteAddr())

	defer func() {
		logEntry.Info("closed connection")
		clientConn.Close()
	}()

	groups, err := rp.AuthorizeConnection(clientConn)
	if err != nil {
		logEntry.WithField("phase", "authorize").Error(err)
		return err
	}
	logEntry = logEntry.WithField("groups", groupNames(groups))
	logEntry.Info("accepted connection")

	serverConn, err := net.Dial("tcp", rp.ServerAddress)
	if err != nil {
		logEntry.WithField("phase", "dial").Error(err)
		return err
	}
	defer serverConn.Close()

	errCh := make(chan error, 2)

	// everything the server says is fair game to the client
	go func() {
		_, err := io.Copy(clientConn, serverConn)
		if err != nil {
			log.WithField("phase", "copy server to client").Error(err)
		}
		errCh <- err
	}()

	// filter what the client can send to the server
	go func() {
		errCh <- rp.FilterConnection(groups, clientConn, serverConn)
	}()

	err = <-errCh
	if err == io.EOF {
		err = nil
	}
	if err != nil {
		logEntry = logEntry.WithError(err)
	}

	_ = <-errCh // make sure both sides of the connection are done
	return err
}

// AuthorizeConnection returns the groups that the specified connection
// is authorized for, based on inspecting the client provided certificate.
func (rp *RedisProxy) AuthorizeConnection(conn net.Conn) ([]Group, error) {
	tlsConn := conn.(*tls.Conn)
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}

	groups := []Group{}
	for _, group := range rp.Groups {
		for _, organizationalUnit := range group.OrganizationalUnits {
			for _, verifiedChain := range tlsConn.ConnectionState().VerifiedChains {
				if len(verifiedChain) < 1 {
					continue
				}
				cert := verifiedChain[0]
				for _, certOU := range cert.Subject.OrganizationalUnit {
					if certOU == organizationalUnit {
						groups = append(groups, group)
					}
				}
			}
		}
	}

	return groups, nil
}

func groupNames(groups []Group) []string {
	rv := make([]string, 0, len(groups))
	for _, g := range groups {
		rv = append(rv, g.Name)
	}
	return rv
}

func commandStr(command [][]byte) []string {
	rv := make([]string, 0, len(command))
	for _, cmdPart := range command {
		rv = append(rv, string(cmdPart))
	}
	return rv
}

// FilterConnection reads incoming traffic from clientConn, checks each command
// against the rules, and if allowed, passes the command to the redis server.
// If the command is not allowed, this function responds with "-ACCESS DENIED" and
// closes the connection.
func (rp *RedisProxy) FilterConnection(groups []Group, clientConn net.Conn, serverConn net.Conn) error {
	logEntry := log.WithField("remote", clientConn.RemoteAddr())
	logEntry = logEntry.WithField("groups", groupNames(groups))

	reader := bufio.NewReader(clientConn)
	for {
		// read the arg count line
		line, _, err := reader.ReadLine()
		if err != nil {
			if err != io.EOF {
				logEntry.WithField("phase", "read_arg_count").Error(err)
			}
			return err
		}
		var count int
		if _, err := fmt.Sscanf(string(line), "*%d\r\n", &count); err != nil {
			logEntry.WithField("phase", "read_arg_count").WithField("line", string(line)).Error(err)
			fmt.Fprintf(clientConn, "-invalid syntax\r\n")
			return err
		}

		command := [][]byte{}
		for i := 0; i < count; i++ {
			line, _, err := reader.ReadLine()
			if err != nil {
				return err
			}
			var size int
			if _, err := fmt.Sscanf(string(line), "$%d\r\n", &size); err != nil {
				logEntry.WithField("phase", "read_size").WithField("line", string(line)).Error(err)
				fmt.Fprintf(clientConn, "-invalid syntax\r\n")
				return err
			}

			buf := make([]byte, size)
			_, err = io.ReadFull(reader, buf)
			if err != nil {
				logEntry.WithField("phase", "read_string").Error(err)
				return err
			}

			newline := [2]byte{}
			if _, err := io.ReadFull(reader, newline[:]); err != nil {
				log.WithField("phase", "read_newline").Error(err)
				return err
			}
			if newline[0] != '\r' || newline[1] != '\n' {
				log.WithField("phase", "read_newline").Errorf("Exprected \\r\\n got %q", string(newline[:]))
				fmt.Fprintf(clientConn, "-invalid syntax\r\n")
				return err
			}

			command = append(command, buf)
		}

		logEntry2 := logEntry.WithField("command", commandStr(command))
		if err := rp.AuthorizeCommand(groups, command); err != nil {
			logEntry2.Error("access denied")
			fmt.Fprintf(clientConn, "-ACCESS DENIED\r\n")
			return fmt.Errorf("client attempted a command which is not allowed")
		}

		// if the command was authorized, send it to the server
		if _, err := fmt.Fprintf(serverConn, "*%d\r\n", len(command)); err != nil {
			logEntry2.Error(err)
			return err
		}
		for _, commandPart := range command {
			if _, err := fmt.Fprintf(serverConn, "$%d\r\n%s\r\n", len(commandPart), commandPart); err != nil {
				logEntry2.Error(err)
				return err
			}
		}
	}
}

// AuthorizeCommand returns a nil error if the specified command is allowed by
// the rules for the specified groups.
func (rp *RedisProxy) AuthorizeCommand(groups []Group, command [][]byte) error {
	for _, group := range groups {
		for _, rule := range rp.Rules {
			if !rule.AppliesToGroup(group) {
				continue
			}
			if !rule.Matches(command) {
				continue
			}
			return nil
		}
	}
	return fmt.Errorf("no rule allows client to invoke %s", command)
}

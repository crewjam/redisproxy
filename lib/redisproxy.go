package redisproxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"regexp"
)

type RedisProxy struct {
	Listener      net.Listener
	ServerAddress string
	Groups        []Group
	Rules         []Rule
}

type Group struct {
	Name                string
	OrganizationalUnits []string
}

type Rule struct {
	Groups   []string
	Commands [][]string
}

func (r Rule) AppliesToGroup(group *Group) bool {
	for _, groupName := range r.Groups {
		if groupName == group.Name {
			return true
		}
	}
	return false
}

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

func (rp *RedisProxy) Run() error {
	for {
		conn, err := rp.Listener.Accept()
		if err != nil {
			return err
		}
		go rp.HandleConnection(conn)
	}
}

func (rp *RedisProxy) AuthorizeConnection(conn net.Conn) (*Group, error) {
	if tlsConn, ok := conn.(*tls.Conn); ok {
		for _, group := range rp.Groups {
			for _, organizationalUnit := range group.OrganizationalUnits {
				for _, verifiedChain := range tlsConn.ConnectionState().VerifiedChains {
					if len(verifiedChain) < 1 {
						continue
					}
					cert := verifiedChain[0]
					for _, certOU := range cert.Subject.OrganizationalUnit {
						if certOU == organizationalUnit {
							return &group, nil
						}
					}
				}
			}
		}
	}
	return nil, fmt.Errorf("connection is not part of any defined group")
}

func (rp *RedisProxy) HandleConnection(clientConn net.Conn) error {
	defer clientConn.Close()

	group, err := rp.AuthorizeConnection(clientConn)
	if err != nil {
		return err
	}

	serverConn, err := net.Dial("tcp", rp.ServerAddress)
	if err != nil {
		return err
	}
	defer serverConn.Close()

	errCh := make(chan error, 2)

	// everything the server says is fair game to the client
	go func() {
		_, err := io.Copy(clientConn, serverConn)
		errCh <- err
	}()

	// filter what the client can send to the server
	go func() {
		errCh <- rp.FilterConnection(group, clientConn, serverConn)
	}()

	err = <-errCh
	<-errCh // receive the other error
	return err
}

func (rp *RedisProxy) FilterConnection(group *Group, clientConn net.Conn, serverConn net.Conn) error {
	reader := bufio.NewReader(clientConn)
	for {
		// read the arg count line
		line, _, err := reader.ReadLine()
		if err != nil {
			return err
		}
		var count int
		if _, err := fmt.Sscanf(string(line), "*%d\r\n", &count); err != nil {
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
				fmt.Fprintf(clientConn, "-invalid syntax\r\n")
				return err
			}

			buf := make([]byte, size)
			_, err = io.ReadFull(reader, buf)
			if err != nil {
				return err
			}

			if b, err := reader.ReadByte(); b != '\r' {
				fmt.Fprintf(clientConn, "-invalid syntax\r\n")
				if err == nil {
					err = fmt.Errorf("invalid syntax")
				}
				return err
			}
			if b, err := reader.ReadByte(); b != '\n' {
				fmt.Fprintf(clientConn, "-invalid syntax\r\n")
				if err == nil {
					err = fmt.Errorf("invalid syntax")
				}
				return err
			}
		}

		if err := rp.AuthorizeCommand(group, command); err != nil {
			fmt.Fprintf(clientConn, "-access denied\r\n")
			return fmt.Errorf("access denied")
		}
	}
}

func (rp *RedisProxy) AuthorizeCommand(group *Group, command [][]byte) error {
	for _, rule := range rp.Rules {
		if !rule.AppliesToGroup(group) {
			continue
		}
		if !rule.Matches(command) {
			continue
		}
		return nil
	}
	return fmt.Errorf("no rule allows %s to invoke %s", group.Name, command)
}

# Redis Proxy

This program is a proxy for redis that adds access controls and TLS client authentication.

You configure this program with a YAML file, which defines groups and rules.

    groups:
      + name: frontend
        ou: ["frontend"]
      + name: web
        ou: ["web"]
    rules:
      + groups: ["frontend"]
        commands: [["^PING$"], ["^SADD$", "^sessions/(.*)$"]]

Invoking it:

    redisproxy \
        -config config.yaml \
        -cert cert.pem -key key.pem -client-ca ca.pem \
        -listen 6380 \
        -server localhost:6379

You can use a TLS client such as [ghostunnel](https://github.com/square/ghostunnel) or [openssl s_client](https://www.openssl.org/docs/manmaster/apps/s_client.html) to connect.

Note #1: This program implements the Redis protocol as described [http://redis.io/topics/protocol](here). It **does not** implement *Inline Commands* (PRs welcome).

Note #2: when a client issues a command that is not allowed, the connection is immediately closed. If the client is pipelining, sending multiple commands without waiting for responses, it may interrupt pending responses. (Again, PRs welcome)
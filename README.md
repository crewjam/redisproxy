# Redis Proxy

This program is a proxy for redis that adds access controls and TLS client authentication.

You configure this program with a YAML file, which defines groups and rules.

    groups:
      - name: frontend
        subjects: ["/CN=frontend"]
      - name: web
        subjects: ["/CN=web"]
    rules:
      - group: frontend
        commands: 
          ["^SADD$", "^sessions/(.*)$"]





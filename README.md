# SSH-as-a-Service - short lifetime certificates for SSH (server and client)

A simple SSH certification authority server. Given a private (CA) key
and a configuration file describing authorised users, the server will
generate short duration certificates granting access for the listed
principals.

To avoid the client needing to have access to private keys, it
contacts the ssh-agent to find the key to use for authentication
purposes and generates an ephemeral key for certification. The
ephemeral key/certificate are stored in ssh-agent for the lifetime of
the certificate.

You probably shouldn't use this in production unless you've checked my
crypto for errors.

# Configuration example

```
---
users:

  # Alice can log in to servers with her own account, or as the privileged sysadm user
  - name: Alice
    key: AAAAC3NzaC1lZDI1NTE5AAAAID2wmSViPXhYY9yjEBnUJJCaV1YBpbKmbIlBzC4EJSj5
    principals: [ alice, sysadm ]

  # Bob may only log in to servers as an unprivileged business-as-usual user
  - name: Bob
    key: AAAAC3NzaC1lZDI1NTE5AAAAILQ2vgbwJjPqhptlTkr9bTjAkHTdwte98rTDijQ+ygjo
    principals: [ bau ]

```

The makefile uses `yq` to convert this to the JSON format that the server reads.

# Server example

`sshaas -key /path/to/ca-private-key-file -lifetime 60 config.json`

By default the server listens on loopback, port 9999. You can change
this using the `-listen` flag (and the `-endpoint` flag to tell
the client where to find the server).

# Client example

```
$ ssh-add -l
256 SHA256:7HrWTqbImQqKVDh7iMWy84h6+kbqz5Hb7BN8gfpM+og my-key (ED25519)
$ sshaas
$ ssh-add -l
256 SHA256:7HrWTqbImQqKVDh7iMWy84h6+kbqz5Hb7BN8gfpM+og my-key (ED25519)
256 SHA256:3FxVOMbBpHIlI426bbgzbGzH+5DEUN9FmmDP4vEPBD0 SSH-as-a-Service (ED25519-CERT)
```

Alternately you can specify the key to use for authentication by comment 

```
$ ssh-add -l
256 SHA256:7HrWTqbImQqKVDh7iMWy84h6+kbqz5Hb7BN8gfpM+og this-one (ED25519)
256 SHA256:JHXy5DxBdzawOgXPbxliACkGtCKQ8AcshlnBWvTfjvo not-this-one (ED25519)
$ sshaas this-one
$ ssh-add -l
256 SHA256:7HrWTqbImQqKVDh7iMWy84h6+kbqz5Hb7BN8gfpM+og this-one (ED25519)
256 SHA256:JHXy5DxBdzawOgXPbxliACkGtCKQ8AcshlnBWvTfjvo not-this-one (ED25519)
256 SHA256:As+6hsinvjdp8MV0DphJzzUfvHoFt9q0V7T7GWTZJKk SSH-as-a-Service (ED25519-CERT)
```

# Process

The client selects an authorised key from those provided by ssh-agent,
and then generates an ephemeral key pair. Using a similar process to JWTs,
the client creates a JSON header which specifies the authorised key
(and its type), and a body containing the public part of ephemeral
key.

The two sections are both base64 encoded, concatenated with a `.` and
signed with the authorised key (via ssh-agent). The signature is
concatenated with a `.` to the other two sections.

The resulting token is then submitted to the server, which validates
that the token is signed by the authorised key, thus proving that the
client is genuine and the request has not been tampered with. If the
authorised key is present in the configuration then the principals
which the key should have access to are determined.

The ephemeral key from the body of the request is signed into a short
lifetime certificate along with the principals and returned to the
client.

The client can then add the private ephemeral key and certificate to
the ssh-agent, thereby allowing access to servers for a limited
time. Once the certificate lifetime expires ssh-agent will
automatically remove the key and certificate.

# TODO

Intercepting and replaying a token is useless unless you have the
ephemeral private key, but I should probably add a replay cache Just
In Case&trade;.

If you are aware of any weakness in the process then please let me know!

# Unix domain socket SOCKS5 protocol extension

This documents the SOCKS5 protocol extension used by `metaproxy` when
run over Unix domain sockets to pass a file descriptor to the client
process, thus avoiding the overhead of passing all traffic through the
proxy process after the initial negotiation.

The SOCKS5 protocol itself is documented in RFC 1928.

This protocol extension requires that the initial negotiation is
performed over a channel over which a socket file descriptor can be
passed. The rest of this specification assumes that this is the
Unix/Linux `SCM_RIGHTS` mechanism; another platform may substitute an
equivalent mechanism.

A client MUST NOT attempt to negotiate this protocol if it not able to
accept a socket file descriptor for any reason, and a server MUST NOT
attempt to grant such a request if it is unable to transmit one.

Note: the following description uses the byte 0xFD as the
authentication mechanism and status code; those are temporary values
pending a permanent assignment.

To negotiate this protocol, a client includes the byte 0xFD as one of
the single-byte authentication mechanisms it is able to use. Once
offered, a client MUST be prepared to accept a file descriptor, no
matter what authentication mechanism is actually requested by the
server.

The server MAY rely on Unix domain credentials passing
(e.g. `SCM_CREDENTIALS`) in choosing to accept this request. An
`SCM_CREDENTIALS` message MUST be attached to the first byte (VER
field) of the first message (authentication methods offer)
transmitted.

The server MAY acknowledge this request by specifying 0xFD as the
authentication type, or it MAY proceed with any other authentication
type, which then proceeds as usual. If the server specifies 0xFD as
the authentication method, the session will proceed exactly as if
authentication method 0x00 (no authentication) was negotiated.

Once the client has offered authentication method 0xFD and the
connection is successful, no matter what authentication method is
actually negotiated, the server MAY pass a socket file descriptor
instead of proxying the data connection, and transmit a status code
0xFD instead of 0x00. The socket file descriptor MUST be attached to
the first byte (VER field) of the request response message. The server
MUST NOT provide a file descriptor unless the connection is
successful.

If no file descriptor is exchanged, but the connection is successful,
both the server and the client MUST proceed according to the unmodified
SOCKS5 protocol.

If the server provides a file descriptor, it MUST be a socket, but it
MAY be a different address family than the client originally requested.

For a CONNECT request (type 0x01):

The file descriptor passed MUST be a connected stream socket. The
client MAY close the control connection any time after receiving the
response message.

Note: The following operations are not yet implemented by metaproxy.

For a BIND request (type 0x02):

If a file descriptor is attached to the first response message, it
MUST be a listening stream socket. In that case, there is no second
response packet and the client MAY treat the listening socket as if it
were directly connected to the Internet for the purpose of this
association.  The client MUST still leave the control connection open,
as the server still MAY terminate the validity of the association
(e.g. by controlling firewall rules or routing) when the control
connection is closed.)

The client MAY close the control connection at any
time after receiving the response message.

If a file descriptor is attached to the second response message, it
MUST be a connected stream socket. The client MAY close the control
connection at any time after receiving the response message.

For a UDP ASSOCATE request (type 0x03), the file descriptor MUST be a
connected or unconnected datagram socket. The client MUST maintain the
control connection until it wishes to terminate the UDP association,
at which time it MUST terminate the control connection and close the
datagram socket.

If the socket is connected, the UDP association proceeds as specified
in section 7 of the SOCKS 5 specification (RFC 1928.)

If the socket is unconnected (getpeername() returns ENOTCONN) the
server indicates that the client should otherwise proceed as if it had
a direct connection to the Internet for the purpose of this
association and the server client MUST NOT attach the SOCKS5 UDP
header specified in section 7 of RFC 1928. The client MUST still leave
the control connection open, as the server still MAY terminate the
validity of the association (e.g. by controlling firewall rules or
routing) when the control connection is closed.)

In this case, the server SHOULD set BND.PORT and BND.ADDR to the port
and addresses visible to the remote peer, as far as that information
is available to it. If either or both fields are entirely unknown, it
MUST set the relevant fields to all zero.

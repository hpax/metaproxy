---
title: "SOCKS5 File Descriptor Passing over Unix Domain Sockets"
abbrev: "SOCKS5 FD Pass"
docname: draft-anvin-socks-unix-fd-pass-00
category: exp
submissionType: independent
ipr: trust200902
area: "Applications and Real-Time"
workgroup: ""
keyword:
  - SOCKS
  - proxy
  - Unix domain socket
  - file descriptor passing
  - SCM_RIGHTS
  - SCM_CREDENTIALS
stand_alone: yes
smart_quotes: no
pi:
  toc: yes
  tocdepth: 3
  sortrefs: yes
  symrefs: yes

author:
  - name: H. Peter Anvin
    org: RosaicLabs
    email: hpa@zytor.com

normative:
  RFC1928:
  RFC2119:
  RFC8174:

informative:
  RFC1929:
  POSIX.1-2024:
    title: "The Open Group Base Specifications Issue 8, 2024 edition
           (IEEE Std 1003.1-2024)"
    author:
      org: IEEE and The Open Group
    date: 2017
    target: https://pubs.opengroup.org/onlinepubs/9799919799/
---

~~~
Internet-Draft                                                H. P. Anvin
draft-anvin-socks-unix-fd-pass-00                             RosaicLabs
Intended status: Experimental                                October 2026
Expires: April 23, 2027
~~~

# SOCKS5 File Descriptor Passing over Unix Domain Sockets

## Abstract

This document specifies an extension to the SOCKS Protocol Version 5
(RFC 1928) that enables a SOCKS5 server operating over a Unix domain
socket to pass a socket file descriptor directly to the client process
using the operating system's ancillary message (`SCM_RIGHTS`) mechanism.
Once the client holds the passed socket, it communicates directly with
the remote endpoint without any further involvement of the proxy
server, eliminating the per-byte overhead of data proxying after the
initial negotiation is complete.  Two new code values (each assigned
by IANA from the appropriate registry) are defined: an authentication
method code `TBD(m)` to signal client capability for file descriptor
receipt, and a reply status code `TBD(r)` that the server sets in the `REP`
field whenever it attaches a file descriptor to a reply message.  `BIND`
and `UDP ASSOCIATE` semantics are extended correspondingly.

## Status of This Memo

This Internet-Draft is submitted in full conformance with the
provisions of BCP 78 and BCP 79.

Internet-Drafts are working documents of the Internet Engineering Task
Force (IETF).  Note that other groups may also distribute working
documents as Internet-Drafts.  The list of current Internet-Drafts is
at https://datatracker.ietf.org/drafts/current/.

Internet-Drafts are draft documents valid for a maximum of six months
and may be updated, replaced, or obsoleted by other documents at any
time.  It is inappropriate to use Internet-Drafts as reference
material or to cite them other than as "work in progress."

This Internet-Draft will expire on April 23, 2027.

## Copyright Notice

Copyright (c) 2026 IETF Trust and the persons identified as the
document authors.  All rights reserved.

This document is subject to BCP 78 and the IETF Trust's Legal
Provisions Relating to IETF Documents
(https://trustee.ietf.org/license-info) in effect on the date of
publication of this document.  Please review these documents carefully,
as they describe your rights and restrictions with respect to this
document.

## Table of Contents

~~~ toc
1.   Introduction
2.   Conventions and Definitions
3.   Overview
  3.1.  Motivation
  3.2.  Design Summary
4.   Method Negotiation
  4.1.  Client Offer
  4.2.  Server Selection
  4.3.  Capability Constraints
5.   Credential Passing
  5.1.  SCM_CREDENTIALS Overview
  5.2.  Protocol Requirements
6.   File Descriptor Delivery
  6.1.  Delivery Point
  6.2.  Preconditions
  6.3.  Fallback Behavior
  6.4.  Message Flow
7.   CONNECT Request Handling
8.   BIND Request Handling
  8.1.  Overview
  8.2.  Association Mode
  8.3.  Connection Mode
  8.4.  Fallback Behavior
9.   UDP ASSOCIATE Request Handling
  9.1.  Overview
  9.2.  Connected Socket Semantics
  9.3.  Unconnected Socket Semantics
  9.4.  Association Lifetime
  9.5.  Fallback Behavior
10.  Security Considerations
  10.1. Transport Scope
  10.2. Credential Verification
  10.3. File Descriptor Injection
  10.4. Privilege Separation
  10.5. Control Connection Lifetime
11.  IANA Considerations
12.  References
  12.1. Normative References
  12.2. Informative References
~~~


## 1. Introduction

The SOCKS Protocol Version 5 [RFC1928] is a widely deployed proxy
protocol that allows client applications to request network connections
through an intermediary server.  In the conventional SOCKS5 model, all
data traffic flows through the proxy server for the entire duration of
the session, even after the initial connection negotiation is complete.
The proxy reads bytes arriving from the client, forwards them to the
remote endpoint, and does the same in reverse: a processing loop that
consumes CPU time and memory bandwidth proportional to application
throughput.

When a SOCKS5 server is deployed as a local intermediary on a
POSIX-conformant system (for example, a privilege-separated helper
process that establishes network connections on behalf of less-privileged
applications), the conventional proxying model wastes resources.  The
operating system already provides a mechanism to pass open file
descriptors between processes as ancillary data attached to a Unix
domain socket message.  This mechanism, defined by POSIX [POSIX.1-2024]
and commonly known as `SCM_RIGHTS`, allows the server to transfer the
established socket connection directly to the client process.  Once the
client holds that socket, it communicates with the remote endpoint
without any further involvement of the proxy server.

This document specifies an extension to SOCKS5 that makes use of this
capability.  Two new code values are defined, each assigned by IANA
from its respective registry.  First, authentication method code `TBD(m)`
is defined for use in SOCKS5 method negotiation: a client that includes
`TBD(m)` in its method offer signals that it is capable of receiving a
socket file descriptor.  Second, reply status code `TBD(r)` is defined as
the value the server sets in the `REP` field whenever it attaches a file
descriptor to a reply message, providing an explicit in-band signal
that an FD accompanies the reply.

A server that supports the extension MAY attach an open socket file
descriptor to its SOCKS5 reply message as `SCM_RIGHTS` ancillary data.
The client then uses the received socket directly for all subsequent
data transfer, and the proxy server is freed from the data-forwarding
burden.

The extension is necessarily limited to transport channels that
support passing network connection objects.  This specification
assumes the POSIX `SCM_RIGHTS` mechanism over Unix domain sockets;
equivalent mechanisms on other platforms may be substituted provided
both endpoints support the same mechanism.  Implementations MUST NOT
offer or exercise this extension over TCP/IP or any other transport
that does not support passing network connection objects.

The extension preserves full backward compatibility.  A server that
does not support it ignores the `TBD(m)` method code and proceeds with
standard SOCKS5.  A client that does not receive an attached file
descriptor on the reply falls back to standard SOCKS5 data proxying
over the control connection.


## 2. Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all
capitals, as shown here.

This document uses the convention from [RFC1928] for hexadecimal
numbers.

The following terms from [RFC1928] are used throughout this document:

**`VER`**
: The SOCKS protocol version number byte.  In SOCKS5 this field always
  carries the value `X'05'`.

**`CMD`**
: The command code byte in a SOCKS5 request message (`CONNECT` = `X'01'`,
  `BIND` = `X'02'`, `UDP ASSOCIATE` = `X'03'`).

**`REP`**
: The reply code byte in a SOCKS5 reply message.  A value of X'00'
  indicates success without an attached file descriptor.  A value of
  `TBD(r)` indicates success with an attached file descriptor (see
  Section 6.2).  Other values indicate errors as defined in
  [RFC1928].

**`ATYP`**
: The address type indicator byte.

**`BND.ADDR`**
: The server-bound address field in a SOCKS5 reply message.

**`BND.PORT`**
: The server-bound port field in a SOCKS5 reply message, in network
  byte order.

The following additional terms are defined for use in this document:

**ClientHello**
: The initial message sent by the client to the server in the SOCKS5
  method negotiation, carrying the protocol version, the number of
  offered authentication methods, and the list of method codes.
  Referred to in [RFC1928] as the "version identifier/method
  selection message".

**ServerHello**
: The response sent by the server to the client in the SOCKS5 method
  negotiation, carrying the protocol version and the selected
  authentication method code.  Referred to in [RFC1928] as the
  "method selection message".

**Control connection**
: The Unix domain socket connection over which the SOCKS5 negotiation
  takes place.  For `CONNECT` requests and `BIND` requests in connection
  mode (Section 8.3), the control connection may be closed by the
  client after receiving the final reply with an attached file
  descriptor.  For `BIND` requests in association mode (Section 8.2)
  and for `UDP ASSOCIATE`, the control connection must remain open for
  the duration of the association; the server MAY revoke the
  association when the control connection closes.

**File descriptor (FD)**
: An open file descriptor representing a socket, as transferred between
  processes via the `SCM_RIGHTS` ancillary data mechanism.

  On some non-POSIX systems (notably Microsoft Windows), a socket may
  be represented by a different kind object than a file descriptor as
  returned by `open()`; in that case the term "file descriptor" in
  this document is to be interpreted as such a socket-referencing
  object.

**SCM_RIGHTS**
: The POSIX ancillary data type used to pass open file descriptors
  between processes as ancillary data on a Unix domain socket message,
  as specified in [POSIX.1-2024].

**SCM_CREDENTIALS**
: A Linux-specific ancillary data type that conveys the PID, UID, and
  GID of the sending process as ancillary data on a Unix domain socket
  message.  Platform-specific equivalents (e.g., LOCAL_CREDS on some
  BSD systems) provide the same function under different names.


## 3. Overview

### 3.1. Motivation

In a standard SOCKS5 deployment, the proxy server operates as a
full relay: after the negotiation phase it copies all bytes from the
client-side socket to the remote-side socket and vice versa, for the
entire lifetime of the connection.  On a loaded system this relay loop
consumes significant CPU and memory bandwidth, particularly for
high-throughput or latency-sensitive connections.

When the SOCKS5 server is a local process on the same host as the
client (for example, a privilege-separated daemon whose only function
is to open network connections on behalf of restricted processes), the
relay overhead is doubly wasteful: all data crosses a kernel socket
boundary twice (client to proxy, proxy to remote) when it need only
cross it once (client to remote) if the client held the remote socket
directly.

### 3.2. Design Summary

This extension solves the relay overhead by using the `SCM_RIGHTS`
mechanism to pass the established remote socket from the proxy server
to the client process.  The key design points are:

1. **Signaling.**  The client signals FD-passing capability by
   including the new authentication method code `TBD(m)` in the METHODS
   field of its SOCKS5 ClientHello message.  This is a capability
   advertisement, not a request for a particular authentication
   scheme.

2. **Credential passing.**  The server may require the client to
   authenticate its Unix identity.  If the client wishes to present
   its credentials, it attaches an `SCM_CREDENTIALS` ancillary message
   to the send call that carries the first byte (`VER`) of the
   ClientHello message.

3. **FD delivery.**  If the server elects to pass a file descriptor
   for a successful request, it attaches the socket as `SCM_RIGHTS`
   ancillary data to the send call that carries the first byte (`VER`)
   of the SOCKS5 reply message, and sets the `REP` field to `TBD(r)`.

4. **Backward compatibility.**  If the server does not pass a file
   descriptor, and the reply indicates success, both sides proceed with
   standard SOCKS5 proxying.  Offering TBD never prevents a session
   from falling back to the unmodified protocol.


## 4. Method Negotiation

### 4.1. Client Offer

A client that supports file descriptor receipt and is prepared to
accept a socket file descriptor MUST include the method code TBD in the
METHODS field of its ClientHello message.  A client MUST NOT include
method code TBD if it is unable to receive a file descriptor (for example,
because the transport is not a Unix domain socket or because the
platform does not support `SCM_RIGHTS`).

The ClientHello message format is defined in Section 3 of [RFC1928]:

~~~
+----+----------+----------+
|VER | NMETHODS | METHODS  |
+----+----------+----------+
| 1  |    1     | 1 to 255 |
+----+----------+----------+
~~~

The METHODS field is a list of NMETHODS one-byte authentication method
codes.  The client includes TBD among these codes to indicate FD-passing
capability; it MAY also include other method codes (e.g., `X'00'` for No
Authentication Required, or `X'02'` for Username/Password Authentication
[RFC1929]) to indicate support for conventional authentication schemes.

Once a client has included TBD in its METHODS offer, it MUST be
prepared to receive a file descriptor as `SCM_RIGHTS` ancillary data
attached to the SOCKS5 reply message, regardless of which
authentication method the server ultimately selects in its ServerHello.
The obligation to accept an FD arises from having offered `TBD(m)`, not
from the server having selected it.  The mechanism by which the client
detects an attached file descriptor is described in Section 6.3.

### 4.2. Server Selection

The server responds with a ServerHello message selecting one
authentication method:

~~~
+----+--------+
|VER | METHOD |
+----+--------+
| 1  |   1    |
+----+--------+
~~~

The server MAY select method TBD to acknowledge the client's
FD-passing offer.  When the server selects TBD as the authentication
method, the session proceeds exactly as if authentication method `X'00'`
(No Authentication Required) had been selected: no additional
authentication sub-negotiation messages are exchanged before the
client sends its request.

The server MAY select any other method it supports, including those
not involving FD passing.  Selecting a method other than `TBD(m)` does not
preclude the server from subsequently attaching a file descriptor to
the reply; the FD delivery decision is made at reply time, conditioned
only on whether the client offered `TBD(m)`.

If the server is unable to proceed with any offered method, it MUST
respond with `METHOD` = `X'FF'` (No Acceptable Methods) as defined in
[RFC1928] and MUST close the connection.

### 4.3. Capability Constraints

A server MUST NOT attach a file descriptor to a reply message if the
client did not include `TBD(m)` in its METHODS offer.

A server MUST NOT attempt to pass a file descriptor if it is unable to
do so, for example because the control connection is not a Unix
domain socket or because the platform does not support `SCM_RIGHTS`.


## 5. Credential Passing

### 5.1. `SCM_CREDENTIALS` Overview

Many Unix-derived operating systems provide a mechanism to convey the
credentials (process identifier, user identifier, and group
identifier) of the sending process as kernel-verified ancillary data
on a Unix domain socket message.  On Linux this mechanism is
`SCM_CREDENTIALS`; equivalent mechanisms exist on BSD-derived systems
(e.g., `LOCAL_CREDS`, `LOCAL_PEEREID`) and other POSIX platforms.
Because the kernel populates the credential fields from the sending
process and prevents forgery, a server receiving such credentials MAY
treat them as authoritative for access control purposes.

A server may use these credentials to apply access control.  For
example, the server may restrict FD passing to processes owned by a
specific UID or belonging to a specific GID, evaluating these
constraints before agreeing to pass a socket to the client.

### 5.2. Protocol Requirements

If the client wishes to present its process credentials to the server,
it MAY attach an `SCM_CREDENTIALS` ancillary message to the send call
that transmits the first byte (the `VER` byte) of the ClientHello
message.  A client MUST NOT attach the credentials to any subsequent
byte of the ClientHello does not satisfy this requirement; a server
MAY accept such credentials, ignore them, or reject the connection and
report an error.

A server that requires credential verification MAY refuse connections
that do not carry credentials.  A server that does not require
credential verification MAY ignore any credentials presented.

Platform-specific equivalents to `SCM_CREDENTIALS` (e.g., `LOCAL_CREDS`
or `LOCAL_PEEREID` on BSD-derived systems) MAY be used in place of
`SCM_CREDENTIALS` on platforms where `SCM_CREDENTIALS` is not available,
provided that both endpoints agree on the mechanism in use.  The
selection of a platform-specific credential mechanism is outside the
scope of this specification.

A server MAY support multiple mechanisms for passing credentials if
applicable to the platform, however, the server SHOULD treat
conflicting received credentials as invalid and either proceed as if
no credentials had been passed or reject the connection with
`METHOD` = `X'FF'` (No Acceptable Methods).


## 6. File Descriptor Delivery

### 6.1. Delivery Point

When the server elects to pass a file descriptor for a successful
request, it MUST attach the socket as `SCM_RIGHTS` ancillary data to the
send call that transmits the first byte (the `VER` byte) of the SOCKS5
reply message.

The SOCKS5 reply message format is defined in Section 6 of [RFC1928]:

~~~
+----+-----+-------+------+----------+----------+
|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+
~~~

The `SCM_RIGHTS` ancillary data MUST be associated with the `send()`
call conveying the `VER` byte.  Implementations that buffer the entire
reply before sending MUST ensure that the `SCM_RIGHTS` ancillary data
is included in the single `send()` call that transmits the `VER` byte
along with the rest of the reply.

### 6.2. Preconditions

When the server attaches a file descriptor to a reply message, it
MUST set the `REP` field to TBD.  The server MUST NOT attach a file
descriptor to a reply message that uses any other `REP` value; in
particular, the server MUST NOT attach a file descriptor to an error
reply.  A successful reply that does not include an attached file
descriptor uses `REP` = `X'00'` as in the unmodified SOCKS5 protocol.

The file descriptor attached MUST be a socket.  It MAY be of a
different address family or protocol type than the client originally
requested, provided it correctly represents the established or
allocated network endpoint.  For example, a server MAY pass an IPv4
socket in response to a request that specified an IPv6 address, if the
server resolved the destination accordingly.

Exactly one file descriptor MUST be attached in the `SCM_RIGHTS`
ancillary message.  Receiving zero file descriptors when `SCM_RIGHTS`
ancillary data is present, or receiving more than one file descriptor,
constitutes a protocol error.  A client that detects such a violation
MUST close all received file descriptors (if any), treat the session as
failed, and close the control connection.

### 6.3. Fallback Behavior

If the server does not attach a file descriptor, a successful reply
carries `REP` = `X'00'`, and both the server and the client MUST
proceed according to the unmodified SOCKS5 protocol as defined in
[RFC1928].  The client MUST be prepared for this fallback regardless
of whether it offered method code `TBD(m)` even if the server
responded with `METHOD` = `TBD(m)`, because the server MAY choose to
not use file descriptor passing for any particular connection.

The client determines whether a file descriptor was passed by
examining both the ancillary data and the `REP` field of the receive
call that delivers the `VER` byte of the reply.  A reply with `REP` =
`TBD(r)` and `SCM_RIGHTS` ancillary data carrying exactly one file
descriptor indicates successful FD delivery.  A reply with `REP` =
`X'00'` and no ancillary data indicates a successful but non-FD
session that follows standard SOCKS5.  A reply with `REP` = `TBD(r)`
but no accompanying `SCM_RIGHTS` data, or with `SCM_RIGHTS` data but
`REP` ≠ `TBD(r)`, constitutes a protocol error; the client MUST treat
the session as failed and close the control connection.

### 6.4. Message Flow

The following diagram illustrates the complete message exchange for a
successful `CONNECT` request with file descriptor passing.  Ancillary
data items carried with each message are shown in square brackets.

~~~
Client                                             Server
  |                                                   |
  |--- ClientHello [SCM_CREDENTIALS optional] ------->|
  |    VER=5, NMETHODS=N, METHODS={...,TBD(m),...}    |
  |                                                   |
  |<-- ServerHello -----------------------------------|
  |    VER=5, METHOD=TBD(m)  (or any other method M)  |
  |                                                   |
  |--- Auth sub-negotiation (if M requires it) ------>|
  |<-- Auth sub-negotiation (if M requires it) -------|
  |                                                   |
  |--- SOCKS5 Request ------------------------------->|
  |    VER=5, CMD=X'01', RSV=0, ATYP, DST.ADDR,       |
  |    DST.PORT                                       |
  |                                                   |
  |<-- SOCKS5 Reply [SCM_RIGHTS: socket fd] ----------|
  |    VER=5, REP=TBD(r), RSV=0, ATYP,                |
  |    BND.ADDR, BND.PORT                             |
  |                                                   |
  |    (Client closes control connection when done)   |
  |                                                   |
  |<====== Direct Data Flow via received socket =====>|
~~~

The following diagram shows the fallback case, where the server does
not attach a file descriptor.  This proceeds identically to standard
SOCKS5.

~~~
Client                                             Server
  |                                                   |
  |--- ClientHello [SCM_CREDENTIALS optional] ------->|
  |    VER=5, NMETHODS=N, METHODS={...,TBD(m),...}    |
  |                                                   |
  |<-- ServerHello -----------------------------------|
  |    VER=5, METHOD=M                                |
  |                                                   |
  |--- Auth sub-negotiation (if M requires it) ------>|
  |<-- Auth sub-negotiation (if M requires it) -------|
  |                                                   |
  |--- SOCKS5 Request ------------------------------->|
  |                                                   |
  |<-- SOCKS5 Reply (no ancillary data) --------------|
  |    VER=5, REP=X'00', ...                          |
  |                                                   |
  |<======= Proxied Data via control connection =====>|
  |              (standard SOCKS5)                    |
~~~


## 7. `CONNECT` Request Handling

For a `CONNECT` request (`CMD` = `X'01'`), if the server elects to pass a
file descriptor, the following requirements apply.

The file descriptor passed MUST be a connected stream socket.  The
socket MUST be connected to the destination address and port specified
in the SOCKS5 request, or to an equivalent endpoint reachable at that
destination.

The `BND.ADDR` and `BND.PORT` fields of the reply message SHOULD contain
the server-side address and port of the socket as observed by the
remote peer, that is, the source address and port used by the server
when connecting to the remote endpoint.  If these values are not known
to the server, it MUST set the relevant fields to all zeros (`0.0.0.0`
with port 0 for IPv4, `[::]` with port 0 for IPv6), as specified in
[RFC1928].

Upon receiving the SOCKS5 reply message with the attached file
descriptor, the client MAY close the control connection at any time.
The client uses the received socket directly for all subsequent data
exchange with the remote endpoint.  From this point forward the
proxy server has no further role in the connection.

If no file descriptor is attached to the reply, the client and server
MUST proceed with standard SOCKS5 data proxying over the control
connection, as specified in [RFC1928].


## 8. `BIND` Request Handling

### 8.1. Overview

For a `BIND` request (`CMD` = `X'02'`), the server may elect to pass a file
descriptor in one of two modes, depending on its capabilities and
policy.  In association mode, the server passes a listening socket in
the first reply message and the client accepts inbound connections
directly.  In connection mode, the server sends a standard first reply
announcing the bound address and then passes a connected socket in the
second reply message.  If the server passes no file descriptor in
either mode, the operation falls back to standard SOCKS5 `BIND`.

### 8.2. Association Mode

To establish association mode, the server MAY attach a file descriptor
to the first reply message.  The following requirements apply.

The file descriptor passed MUST be a listening stream socket.  The
`BND.ADDR` and `BND.PORT` fields of the first reply message MUST contain
the address and port to which the listening socket is bound.  `REP` in
the first reply MUST be set to `TBD(r)`.

There is no second reply message in this mode.  The client accepts
inbound connections directly by calling `accept()` on the received file
descriptor.

The client MUST maintain the control connection for the duration of
the association.  The server MAY enforce access control, firewall
rules, or routing policy tied to the existence of the control
connection and SHOULD revoke any such policy when the control
connection closes.  To terminate the association, the client MUST
close the control connection and SHOULD close the received socket.

### 8.3. Connection Mode

In connection mode, the server sends two reply messages, similar to
the standard SOCKS5 `BIND` operation described in Section 6 of
[RFC1928].

The first reply message is sent after the server has bound a local
address.  This reply carries `REP` = `X'00'` and no attached file
descriptor, and the `BND.ADDR` and `BND.PORT` fields contain the address
and port to which the server has bound.  The client uses this
information to coordinate with the peer that will initiate the inbound
connection.

After the inbound connection arrives, the server sends the second
reply message.  This reply carries `REP` = `TBD(r)`, and the server MUST
attach a connected stream socket as `SCM_RIGHTS` ancillary data to the
send call that transmits the `VER` byte of this second reply.  The
attached socket MUST be connected to the inbound peer.

Upon receiving the second reply message with the attached file
descriptor, the client MAY close the control connection at any time.
The client uses the received socket directly for all subsequent data
exchange with the inbound peer.

### 8.4. Fallback Behavior

If no file descriptor is attached in either reply, the client and
server MUST proceed with the standard SOCKS5 `BIND` operation as
specified in Section 6 of [RFC1928], including the second reply
message.


## 9. `UDP ASSOCIATE` Request Handling

### 9.1. Overview

For a `UDP ASSOCIATE` request (`CMD` = `X'03'`), if the server elects to pass
a file descriptor, the file descriptor MUST be a datagram socket.  The
socket MAY be in either of two states: connected (i.e., a remote
address is bound such that `getpeername()` succeeds) or unconnected
(i.e., `getpeername()` returns `ENOTCONN` or an equivalent error).  These
two states have different semantics for the client, as described in the
following sections.

In all cases the `UDP ASSOCIATE` reply message format is as defined in
Section 7 of [RFC1928]:

~~~
+----+-----+-------+------+----------+----------+
|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+
~~~

The file descriptor is attached to the send call that transmits the
`VER` byte of this reply, as specified in Section 6.1.

### 9.2. Connected Socket Semantics

If the received datagram socket is connected (`getpeername()` succeeds),
the received socket is connected to the server's UDP relay endpoint.
Passing the socket file descriptor in this case avoids the overhead
of socket allocation and binding on the client side, while the
server's relay remains in the data path to perform destination
multiplexing and source-address tagging.  The UDP association proceeds
as specified in Section 7 of [RFC1928]: the server's UDP relay
forwards datagrams on behalf of the client, and SOCKS5 UDP header
encapsulation is required so that the relay can determine the
destination of each outbound datagram and attach source address
information to each inbound datagram.  The client MUST attach the
SOCKS5 UDP request header to each datagram sent via the received
socket, and MUST process the SOCKS5 UDP response header on each
datagram received via the received socket.

The SOCKS5 UDP request header format is reproduced here for reference
(from Section 7 of [RFC1928]):

~~~
+----+------+------+----------+----------+----------+
|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
+----+------+------+----------+----------+----------+
| 2  |  1   |  1   | Variable |    2     | Variable |
+----+------+------+----------+----------+----------+
~~~

### 9.3. Unconnected Socket Semantics

If the received datagram socket is unconnected (`getpeername()` returns
`ENOTCONN` or an equivalent error for a non-blocking socket, or the
socket has no peer address), the server indicates that the client has
a path for direct UDP communication for the purposes of this
association.  In this case:

- The client MUST NOT attach the SOCKS5 UDP request header defined in
  Section 7 of [RFC1928] to datagrams sent via the received socket.

- The client MUST NOT expect the SOCKS5 UDP response header to be
  present on datagrams received via the received socket.

- The client MUST treat the socket as a direct UDP socket, sending and
  receiving application data without SOCKS5 encapsulation.

When an unconnected datagram socket is passed, the server SHOULD set
`BND.ADDR` and `BND.PORT` in the reply to the address and port visible to
remote peers (for example, the external address and port assigned by a
network address translator (NAT), if that information is available to
the server).  If either or both fields are entirely unknown to the
server, the server MUST set the unknown fields to all zeros (`0.0.0.0`
with port 0 for IPv4, `[::]` with port 0 for IPv6).

### 9.4. Association Lifetime

Regardless of whether the received datagram socket is connected or
unconnected, the client MUST maintain the control connection for the
entire duration of the UDP association.  The control connection
represents the lifetime of the association: the server MAY enforce
access control, firewall rules, or routing policy that is tied to the
existence of the control connection and SHOULD revoke any such policy
when the control connection is closed.

To terminate the UDP association, the client MUST close the control
connection and SHOULD close the datagram socket received via `SCM_RIGHTS`.

### 9.5. Fallback Behavior

If no file descriptor is attached to the reply, and the reply code
indicates success, the client and server MUST proceed with standard
SOCKS5 `UDP ASSOCIATE` processing as specified in Section 7 of [RFC1928].


## 10. Security Considerations

### 10.1. Transport Scope

This extension is applicable to SOCKS5 servers operating over Unix
domain socket connections, or over any other connection type for which
the underlying system provides out-of-band mechanisms equivalent to
`SCM_RIGHTS` (for file descriptor passing) and optionally the
`SCM_CREDENTIALS` (for kernel-verified client credential passing).
The exact nature of such system-specific mechanisms, and the means by
which endpoints determine whether they are available, are out of scope
for this document.

This extension MUST NOT be used over TCP/IP connections, named pipes,
or any other transport unless it supports the `SCM_RIGHTS` mechanism
(or equivalent).  A server MUST ignore the `TBD(m)` method code if it
receives it over a transport that lacks the necessary out-of-band
mechanisms.

### 10.2. Credential Verification

The server SHOULD verify the `SCM_CREDENTIALS` ancillary data presented
by the client before agreeing to pass socket file descriptors.
`SCM_CREDENTIALS` conveys the UID, GID, and PID of the connecting
process; the kernel enforces that a process may not forge credentials
belonging to another process's UID or GID unless it holds the
`CAP_SETUID` or `CAP_SETGID` capabilities (Linux privilege tokens that
allow a process to assume arbitrary user or group identities).  This
makes credential-based access control meaningfully stronger than
application-layer authentication alone in a local deployment.

Credential data reflects the identity of the process at the time of
the send call.  If a process can change its UID or GID between the
time it sends the ClientHello and the time the server evaluates the
credentials, the server's access control decision may be based on
stale information.  Servers SHOULD complete the credential evaluation
promptly after receiving the ClientHello.

### 10.3. File Descriptor Injection

A server MUST only pass file descriptors that it has explicitly opened
or received as part of handling the specific SOCKS5 request.  Passing
file descriptors to filesystem files, pipes, device nodes, or any
resource other than the socket established for the current request is
outside the scope of this specification and constitutes a security
vulnerability.

A client receiving a file descriptor SHOULD verify that the received
descriptor refers to a socket before using it.  A suitable verification
method is to call `getsockopt()` with `SO_TYPE`, or to call `fstat()` and
check that the file descriptor has type `S_IFSOCK`.  A client receiving
a file descriptor that does not refer to a socket SHOULD treat this as
a fatal protocol error, close the received descriptor, and close the
control connection.

An implementation that accepts file descriptors over `SCM_RIGHTS` without
verifying the descriptor type is vulnerable to being directed to treat
an arbitrary file descriptor (including a file descriptor pointing to a
sensitive filesystem resource) as a network socket.

### 10.4. Privilege Separation

This extension is designed to support privilege-separated architectures
in which a privileged helper process (the SOCKS5 server) establishes
network connections on behalf of a less-privileged client process.  By
passing the socket directly to the client, the server avoids the need
to remain in the data path, which reduces the server's ongoing exposure
to client-controlled data and limits the consequences of any
vulnerability in the server process.

Implementations SHOULD ensure that the listening socket path for the
SOCKS5 server has filesystem permissions that restrict which processes
may connect.  The combination of discretionary access control (DAC)
enforced by filesystem permissions and `SCM_CREDENTIALS`-based
verification provides a defense-in-depth access control model.  The
filesystem permission check prevents unauthorized processes from
reaching the negotiation phase at all; the credential check provides a
second layer of verification at the protocol layer.

Servers that operate in a high-privilege context (e.g., running as
root or with `CAP_NET_ADMIN`, a Linux capability that grants broad
network administration privileges) SHOULD apply strict access control
before passing file descriptors to client processes, because the passed
socket represents a fully established network connection that bypasses
any further policy enforcement by the server.

### 10.5. Control Connection Lifetime

For `UDP ASSOCIATE` sessions (Section 9), the control connection
represents the binding between the client and the server's network
policy.  Any firewall rules, routing entries, NAT bindings, or other
network state that the server establishes on behalf of the client MUST
be released when the control connection closes, whether the close
occurs normally or due to error.  Failure to release such state when
the control connection closes would allow a terminated association to
persist, potentially leaving network access permanently open beyond its
intended lifetime.


## 11. IANA Considerations

### SOCKS Method Values Registry

IANA is requested to assign a value in the IANA-assigned range
(`X'03'`-`X'7F'`) of the "SOCKS Method Values" registry for the
following entry.  This assignment was previously requested in IANA
request number 1453807.

~~~
+--------+----------------------------------------------+-----------+
| Value  | Description                                  | Reference |
+--------+----------------------------------------------+-----------+
| TBD(m) | File Descriptor Passing (Unix Domain Socket) | [RFCXXXX] |
+--------+----------------------------------------------+-----------+
~~~

The assigned value will be used as the method code throughout this
specification wherever `TBD(m)` appears.

### SOCKS Reply Codes Registry

IANA is requested to assign a value in the "SOCKS Reply Codes"
registry for the following entry.

~~~
+--------+----------------------------------------------+-----------+
| Value  | Description                                  | Reference |
+--------+----------------------------------------------+-----------+
| TBD(r) | File Descriptor Passed (Unix Domain Socket)  | [RFCXXXX] |
+--------+----------------------------------------------+-----------+
~~~

The assigned value will be used as the reply status code (`REP` field)
throughout this specification wherever `TBD(r)` appears.

\[RFC Editor note: Replace `TBD(m)` and `TBD(r)` with the appropriate
IANA-assigned code values and replace RFCXXXX with the RFC number
assigned to this document.\]


## 12. References

### 12.1. Normative References

**[RFC1928]**
: Leech, M., Ganis, M., Lee, Y., Kuris, R., Koblas, D., and L. Jones,
  "SOCKS Protocol Version 5", RFC 1928, DOI 10.17487/RFC1928,
  March 1996.
  &lt;https://www.rfc-editor.org/info/rfc1928&gt;

**[RFC2119]**
: Bradner, S., "Key words for use in RFCs to Indicate Requirement
  Levels", BCP 14, RFC 2119, DOI 10.17487/RFC2119, March 1997.
  &lt;https://www.rfc-editor.org/info/rfc2119&gt;

**[RFC8174]**
: Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key
  Words", BCP 14, RFC 8174, DOI 10.17487/RFC8174, May 2017.
  &lt;https://www.rfc-editor.org/info/rfc8174&gt;

### 12.2. Informative References

**[RFC1929]**
: Leech, M., "Username/Password Authentication for SOCKS V5",
  RFC 1929, DOI 10.17487/RFC1929, March 1996.
  &lt;https://www.rfc-editor.org/info/rfc1929&gt;

**[POSIX.1-2024]**
: IEEE and The Open Group, "The Open Group Base Specifications
  Issue 8, 2024 edition (IEEE Std 1003.1-2024)", 2024.
  &lt;https://pubs.opengroup.org/onlinepubs/9799919799/&gt;


## Author's Address

H. Peter Anvin
RosaicLabs
Email: hpa@zytor.com

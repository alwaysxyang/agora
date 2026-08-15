# HTTP CONNECT Trace Target Design

Status: implemented and verified

Date: 2026-08-15

## Problem

When a sandboxed process uses an application-level HTTP proxy, the socket connects to the proxy
endpoint, for example `127.0.0.1:1087`, while its first request identifies a logical target such as
`CONNECT chatgpt.com:443`. The network inspector currently keeps only the normalized host and drops
the CONNECT port. Trace Viewer then combines that host with the socket destination port and displays
the incorrect mixed endpoint `chatgpt.com:1087`.

## Scope

- Parse the authority of HTTP `CONNECT` requests as a logical target host and port.
- Keep `destination_ip` and `destination_port` as the actual TCP endpoint.
- Add optional `target_host` and `target_port` fields to network events and compact audit records.
- Advance the public event schema from version 8 to version 9 for the added network fields.
- Prefer `target_host:target_port` as the Trace Viewer title when both fields are present.
- Show both the logical target and actual TCP endpoint in event details.
- Preserve existing direct HTTP, TLS SNI, authorization, connection, and audit behavior.

SOCKS and other proxy protocols are out of scope. The implementation does not infer port 443 from a
hostname or TLS SNI.

## Data Flow

The protocol inspector recognizes a complete HTTP `CONNECT` request and parses its request-target
authority. A valid DNS host and explicit port become the observation's logical target. Network event
construction copies that target while continuing to populate the destination from the intercepted
`connect` address. Compact audit serialization preserves both groups of fields, and Trace Viewer uses
the logical target for its title without rewriting the actual destination.

Malformed, incomplete, IP-only, or portless authorities do not create a logical target. Existing
inspection fallback behavior remains unchanged, so the viewer uses the current destination-based
title when no complete logical target is available.

## Testing

- HTTP inspection extracts `chatgpt.com:443` from a CONNECT request.
- Network event construction retains `127.0.0.1:1087` and separately records the logical target.
- Compact audit output carries both endpoints.
- Trace Viewer titles the event `chatgpt.com:443` while its detail retains
  `destination_ip=127.0.0.1` and `destination_port=1087`.
- Direct connections and HTTP requests without a CONNECT target retain their existing behavior.

## Trade-offs

Adding explicit target fields changes several internal schemas but avoids overloading `domain` or
guessing a port. It also leaves room for another protocol to provide the same logical fields later
without adding that protocol in this change.

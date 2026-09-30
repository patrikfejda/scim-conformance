# Findings: i2scim 0.10.4 (in-memory MemoryProvider)

Target: `independentid/i2scim-universal:latest` (server v0.10.4), `MemoryProvider` backend, security disabled, root SCIM path `/`. Run date: 2026-09-30. i2scim is a reference-grade implementation by a SCIM RFC author, so a finding here is worth reporting carefully — verified manually beyond the runner.

Result: 23/28 pass. One real server-error finding, plus two advisory notes.

## Finding: PATCH `add` to a multi-valued attribute crashes with HTTP 500 (MemoryProvider)

A spec-valid PATCH `add` to `emails` (and identically to Group `members`) returns HTTP 500:

```
PATCH /Users/{id}
{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
 "Operations":[{"op":"add","path":"emails","value":[{"value":"work@x.invalid","type":"work"}]}]}
-> 500 Internal Server Error (HTML error page)
```

Server log:

```
java.lang.ClassCastException: Unable to compare Value types
    at com.independentid.scim.backend.memory.MemoryProvider.patch(MemoryProvider.java:562)
    at com.independentid.scim.op.PatchOp.doOperation(PatchOp.java:129)
```

The Group `members` PATCH add hits the same code path with the same 500. The request is valid per RFC 7644 §3.5.2.1 (add to a multi-valued attribute, value is an array of members to add), so a 500 is a server-side defect, not a rejection. It appears specific to the in-memory `MemoryProvider`; the MongoDB backend was not tested and may differ.

**Not reported upstream yet** — pending confirmation of whether to file (and re-test against the Mongo backend first).

## Advisory notes (recorded in the matrix, not bugs)

- `ServiceProviderConfig` does not declare an `etag` capability. RFC 7643 §5 lists it, but it is commonly omitted; the runner treats this as advisory precisely because a reference implementation like i2scim omits it. (This observation is what prompted splitting the runner's capability check.)
- Responses use a non-`application/scim+json` Content-Type (advisory per RFC 7644 §3.1).

## Reproduction

```
docker run -d --name i2scim -p 8082:8080 \
  -e scim.prov.providerClass=com.independentid.scim.backend.memory.MemoryProvider \
  -e scim.security.enable=false \
  independentid/i2scim-universal:latest
scim-conformance --base-url http://localhost:8082
```

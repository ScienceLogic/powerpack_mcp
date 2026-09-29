# Release notes — Powerpack MCP Server

Known limitations and behaviour worth stating plainly to anyone deploying or calling this service.

**Entries describe measured behaviour, not intent.**

---

## Known limitations

### `sl1_graphql_introspect` returns the full schema regardless of the caller's rights

`sl1_graphql_introspect` returns SL1's complete GraphQL schema — **157 query fields and 261
mutations, including destructive ones** — to **any authenticated caller**, irrespective of that
caller's SL1 permissions.

**This is schema shape, not data.** Verified on SL1 12.5.21 with a restricted account: it could
enumerate the `credentials` query field, but was **denied** (`RESTRICTED_ACCESS`) when it actually
queried it, while an administrator account was granted the identical query. Permissions *are*
enforced on execution; they are **not** applied to introspection.

**What this means in practice**: treat an introspection result as a catalogue of what the platform
offers, not as a statement of what the caller may do. Do not use it to infer a caller's entitlements,
and expect a mutation that appears in the schema to be refused at execution time if the caller lacks
rights.

This is expected SL1 platform behaviour — introspection is unfiltered in SL1's GraphQL
implementation — and is not a defect in this service.

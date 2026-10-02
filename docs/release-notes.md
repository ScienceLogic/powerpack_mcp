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

### The passthroughs refuse to read credential secrets

`sl1_graphql`, `sl1_rest_request`, `sl1_rest_search` and `sl1_rest_describe` used to return stored
credential secrets to any caller whose SL1 account could read credentials — the same secrets
`sl1_list_credentials` and `sl1_get_credential` withhold. SL1's own masking did not close this: it
masks `password` (`************`) but does not mark `authHeader`, `tokenKey`, `httpHeader1`/`2`,
`httpHeaders` or `opts` as secret.

They now refuse, **before anything is sent**, with a `validation_blocked` error pointing to the
typed readers:

- in GraphQL, inside a credential (under a field named with `cred`, or a fragment on a credential
  type), any field not on the measured allowlist of non-secret metadata. The typed credential
  types (`snmpCredentials`, `Device.snmpReadCredential`, ...) expose secrets under their own names,
  such as `snmpReadOnlyCommunity` and `curlProxyPassword`, so only what has been classified safe
  may be selected. The `credentialFields` templates have their own list, which includes
  `definition`;
- in GraphQL, on any type, a field whose name matches a secret pattern (`password`, `pwd`,
  `community`, `secret`, `token`, `jwt`, `hash`, `cookie`, `header`, ...), less measured metadata
  such as `passwordStrength`: this covers `Account.hash`, `AgentTokenSecret.jwt`,
  `CollectorToken.token` and the web-content and SOAP monitors' passwords, cookies and headers;
- a search, sort or filter on any of those, whether written as a string, an enum value, a variable
  default or a variable;
- any REST credential path other than the plain `credential` and `credential/<type>` indexes, those
  indexes with `extended_fetch`, a filter or a sort, and every write to a credential path;
- on any REST path, `filter.`/`order.` on a secret-named field or on `verification_answer` or
  `verification_question`, `link_disp_field` naming anything but a plain display field, and a
  percent-encoded `..`;
- a Guided Discovery workflow with an action the GraphQL rule refuses, before the session is
  created and in a dry run.

Aliases, fragments, comments and strings cannot hide or fake a GraphQL selection, because the
document is parsed; a document that does not parse is refused. Every passthrough response, and
`sl1_create_guided_discovery_session`'s, is also scrubbed: credential objects are reduced to their
allowlisted fields, and secret-named keys are dropped wherever they appear.

**What this means in practice**: read credentials with `sl1_list_credentials` and
`sl1_get_credential`, and write them with the typed credential tools. Through `sl1_graphql`,
credential queries may select only metadata, and the create, update and duplicate mutations only
metadata in their results. Deleting access keys or agent tokens (`deleteAccessKey`,
`deleteAgentTokenSecret`) is refused too, because the names match the secret patterns.

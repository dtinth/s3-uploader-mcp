# S3 Uploader MCP

A stateless, multi-tenant MCP server that issues presigned S3 upload URLs.
End-users paste their own S3-compatible storage credentials into an
authorization form; those credentials are encrypted into a bearer token so the
MCP server can sign URLs without the agent ever seeing the raw keys.

## Language

**Operator**: The person who deploys and maintains this server. _Avoid_:
Deployer, admin, host

**End-user**: The person who connects their MCP client to this server and pastes
their storage config into the authorization form. _Avoid_: Tenant, customer,
resource owner

## Relationships

- An **Operator** deploys the server for one or more **End-users**
- An **End-user** configures the server with their own storage credentials via
  the authorization form

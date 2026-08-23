# GraphQL (live HTTP)

`http://HOST:PORT/`. A GraphQL API at `POST /graphql`. The docs only mention
`me` and `users`, but introspection is enabled — enumerate `__schema` to find
every field, including an undocumented `secretFlag`. Its schema description tells
you how it is gated (an internal debug header, not real authorization). Satisfy
the gate and query it.

    POST /graphql {"query":"{ __schema { queryType { fields { name description } } } }"}

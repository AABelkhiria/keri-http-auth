# KERIA authentication reference vectors

Signed requests and responses recorded from KERIA's authentication middleware. `reference_sha` and
`keripy_version` in `v1.json` name what produced them. The generator is not in this repository, so
the file's SHA-256 is recorded here: `cc77e196bfb8df9f003902d53acb6843fe9dbf3dfbd4a154114d70d27d7b110d`.

Six malformed requests answer `500` there because an exception escapes the middleware.
`RequestVerifier` refuses them.

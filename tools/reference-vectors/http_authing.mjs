// Generates and checks request-authentication vectors from the compiled pinned signify-ts checkout.
//
// The signature base a request commits to is internal to `siginput` and to `Authenticater.verify`:
// neither returns it. Both reach it through an injected object -- `signer.sign(ser)` on the signing
// side and `verfer.verify(sig, ser)` on the verifying side -- so a thin recorder wrapped around the
// real key captures the exact bytes while the real primitive still runs. Every base below is
// therefore the reference's own, not a reconstruction.
import { readFileSync, writeFileSync } from "node:fs";

import { b } from "../../reference/signify-ts/dist/keri/core/core.js";
import { Salter } from "../../reference/signify-ts/dist/keri/core/salter.js";
import { Verfer } from "../../reference/signify-ts/dist/keri/core/verfer.js";
import {
  siginput,
  desiginput,
  normalize,
  HEADER_SIG_INPUT,
  HEADER_SIG_TIME,
} from "../../reference/signify-ts/dist/keri/core/httping.js";
import { Authenticater } from "../../reference/signify-ts/dist/keri/core/authing.js";
import { serializeDictionary } from "../../reference/signify-ts/node_modules/structured-headers/dist/index.js";
import libsodium from "../../reference/signify-ts/node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

await libsodium.ready;

const referenceSha = "ae92eceb8e776ad57669707bff7f84db9390b711";

// `siginput` reads the wall clock through `nowUTC()`, which is `new Date()`. The pinned unit tests
// freeze it with `vitest.spyOn(utilApi, 'nowUTC')`; a plain Node script freezes the global `Date`
// instead, to the same instant, so `created` is the 1609459200 those tests assert.
const FROZEN_ISO = "2021-01-01T00:00:00.000Z";
const FROZEN_MS = Date.parse(FROZEN_ISO);
const RealDate = Date;
class FrozenDate extends RealDate {
  constructor(...args) {
    if (args.length === 0) {
      super(FROZEN_MS);
    } else {
      super(...args);
    }
  }
  static now() {
    return FROZEN_MS;
  }
}
globalThis.Date = FrozenDate;

// The salt both pinned tests use. It is their own public constant, so no secret is stored.
const SALT = "0123456789abcdef";
const salter = new Salter({ raw: b(SALT) });
// `salter.signer()` defaults: Ed25519 seed, transferable, empty path, the salter's own tier, and
// the production Argon2 profile.
const signer = salter.signer();

/** Wraps a signer so the exact bytes it is asked to sign are captured. */
function recordingSigner(inner) {
  const captured = {};
  return {
    captured,
    signer: {
      verfer: inner.verfer,
      sign(ser, index) {
        captured.base = new TextDecoder().decode(ser);
        return index === undefined ? inner.sign(ser) : inner.sign(ser, index);
      },
    },
  };
}

/** Wraps a verifier so the exact bytes it is asked to verify are captured. */
function recordingVerfer(inner) {
  const captured = {};
  return {
    captured,
    verfer: {
      code: inner.code,
      raw: inner.raw,
      qb64: inner.qb64,
      verify(sig, ser) {
        captured.base = typeof ser === "string" ? ser : new TextDecoder().decode(ser);
        return inner.verify(sig, ser);
      },
    },
  };
}

const headerPairs = (headers) => [...headers.entries()];

function rejected(operation) {
  try {
    const value = operation();
    return { threw: false, error_category: null, error_message: null, value: value ?? null };
  } catch (error) {
    return {
      threw: true,
      error_category: error?.constructor?.name ?? "Unknown",
      error_message: String(error?.message ?? error),
      value: null,
    };
  }
}

function describeInputage(input) {
  return {
    name: input.name,
    fields: input.fields,
    created: input.created ?? null,
    expires: input.expires ?? null,
    nonce: input.nonce ?? null,
    keyid: input.keyid ?? null,
    context: input.context ?? null,
    alg: input.alg ?? null,
  };
}

/** One `siginput` call, recording its inputs, the base it signed, and what it emitted. */
function siginputCase(name, note, { label, method, path, headers, fields, params = {} }) {
  const recorder = recordingSigner(signer);
  const [header, sig] = siginput(recorder.signer, {
    name: label,
    method,
    path,
    headers,
    fields,
    ...params,
  });
  const value = header.get(HEADER_SIG_INPUT);
  return {
    name,
    note,
    input: {
      label,
      method,
      path,
      headers: headerPairs(headers),
      fields,
      expires: params.expires ?? null,
      nonce: params.nonce ?? null,
      keyid: params.keyid ?? null,
      context: params.context ?? null,
      alg: params.alg ?? null,
    },
    signature_base: recorder.captured.base,
    signature_input_header: value,
    signature_qb64: sig.qb64,
    // Reverse direction: the reference reads the exact header bytes back.
    reparsed: desiginput(value).map(describeInputage),
  };
}

const KEYID = signer.verfer.qb64;

// The headers the pinned `httping.test.ts` and `authing.test.ts` sign over.
const requestHeaders = () =>
  new Headers([
    ["Content-Type", "application/json"],
    ["Content-Length", "256"],
    ["Connection", "close"],
    ["Signify-Resource", "EWJkQCFvKuyxZi582yJPb0wcwuW3VXmFNuvbQuBpgmIs"],
    [HEADER_SIG_TIME, "2022-09-24T00:05:48.196795+00:00"],
  ]);

const siginputCases = [
  siginputCase(
    "httping_unit_test",
    "the pinned test/core/httping.test.ts case: mixed-case header field names, kept verbatim in both the covered list and the base",
    {
      label: "sig0",
      method: "POST",
      path: "/signify",
      headers: requestHeaders(),
      fields: ["Signify-Resource", "@method", "@path", "Signify-Timestamp"],
      params: { alg: "ed25519", keyid: KEYID },
    },
  ),
  siginputCase("derived_components_only", "only @method and @path are covered", {
    label: "signify",
    method: "GET",
    path: "/identifiers/aid1",
    headers: requestHeaders(),
    fields: ["@method", "@path"],
    params: { alg: "ed25519", keyid: KEYID },
  }),
  siginputCase("header_components_only", "no derived component at all", {
    label: "signify",
    method: "DELETE",
    path: "/",
    headers: requestHeaders(),
    fields: ["signify-resource", "signify-timestamp"],
    params: { alg: "ed25519", keyid: KEYID },
  }),
  siginputCase(
    "every_parameter",
    "all six parameters, pinning the order they take in the base and in the header",
    {
      label: "signify",
      method: "PUT",
      path: "/identifiers/aid1/endroles",
      headers: requestHeaders(),
      fields: ["@method", "@path", "signify-resource", "signify-timestamp"],
      params: {
        expires: 1609545600,
        nonce: "0AAxyz-_TESTnonce012345",
        keyid: KEYID,
        context: "keria",
        alg: "ed25519",
      },
    },
  ),
  siginputCase("no_parameters", "only the mandatory created parameter", {
    label: "signify",
    method: "POST",
    path: "/boot",
    headers: requestHeaders(),
    fields: ["@method", "@path"],
  }),
  siginputCase("percent_encoded_path", "a path carrying percent escapes is written verbatim", {
    label: "signify",
    method: "GET",
    path: "/oobi/EBfd%2Fpath",
    headers: requestHeaders(),
    fields: ["@method", "@path"],
    params: { alg: "ed25519", keyid: KEYID },
  }),
  // An HTTP field value is a ByteString, so every code unit must be at most 255: `Headers` refuses
  // anything above Latin-1 outright. A Latin-1 value is accepted and then UTF-8 encoded into the
  // signed bytes, so the header carries one byte and the signature commits to two.
  siginputCase("latin1_header_value", "a covered header value outside ASCII but inside Latin-1", {
    label: "signify",
    method: "POST",
    path: "/challenges",
    headers: new Headers([
      ["Signify-Resource", "EWJkQCFvKuyxZi582yJPb0wcwuW3VXmFNuvbQuBpgmIs"],
      ["X-Note", "héllo"],
    ]),
    fields: ["@method", "@path", "signify-resource", "x-note"],
    params: { alg: "ed25519", keyid: KEYID },
  }),
];

/** One `Authenticater.sign` call, recording the base and both emitted headers. */
function authenticatorSignCase(name, note, { method, path, headers, fields }) {
  const recorder = recordingSigner(signer);
  const authenticator = new Authenticater(recorder.signer, signer.verfer);
  const result = authenticator.sign(headers, method, path, fields);
  return {
    name,
    note,
    method,
    path,
    request_headers: headerPairs(headers),
    fields: fields ?? null,
    signature_base: recorder.captured.base,
    signature_input_header: result.get(HEADER_SIG_INPUT),
    signature_header: result.get("Signature"),
  };
}

const authenticatorSignCases = [
  authenticatorSignCase(
    "authing_unit_test",
    "the pinned test/core/authing.test.ts case: POST /boot with the default covered fields",
    { method: "POST", path: "/boot", headers: requestHeaders() },
  ),
  authenticatorSignCase("explicit_fields", "an explicit covered-field list replaces the defaults", {
    method: "GET",
    path: "/identifiers",
    headers: requestHeaders(),
    fields: ["@method", "@path"],
  }),
];

/** One `Authenticater.verify` call, recording the base it reconstructed. */
function authenticatorVerifyCase(name, note, { method, path, headers, verificationKey }) {
  const recorder = recordingVerfer(new Verfer({ qb64: verificationKey }));
  const authenticator = new Authenticater(signer, recorder.verfer);
  const outcome = rejected(() => authenticator.verify(headers, method, path));
  return {
    name,
    note,
    method,
    path,
    response_headers: headerPairs(headers),
    verification_key: verificationKey,
    signature_base: recorder.captured.base ?? null,
    verified: outcome.threw ? null : outcome.value,
    threw: outcome.threw,
    error_message: outcome.error_message,
  };
}

// Exactly the response the pinned `test/core/authing.test.ts` verifies.
const RESPONSE_KEY = "DMZh_y-H5C3cSbZZST-fqnsmdNTReZxIh0t2xSTOJQ8a";
const RESPONSE_SIGNATURE =
  "0BDLh8QCytVBx1YMam4Vt8s4b9HAW1dwfE4yU5H_w1V6gUvPBoVGWQlIMdC16T3WFWHDHCbMcuceQzrr6n9OULsK";
const responseHeaders = (overrides = {}) =>
  new Headers([
    ["Content-Length", "898"],
    ["Content-Type", "application/json"],
    ["Signature", overrides.signature ?? `indexed="?0";signify="${RESPONSE_SIGNATURE}"`],
    [
      HEADER_SIG_INPUT,
      overrides.signatureInput ??
        [
          'signify=("signify-resource" "@method" "@path" "signify-timestamp")',
          "created=1684715820",
          'keyid="EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei"',
          'alg="ed25519"',
        ].join(";"),
    ],
    ["Signify-Resource", "EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei"],
    [HEADER_SIG_TIME, "2023-05-22T00:37:00.248708+00:00"],
  ]);

const authenticatorVerifyCases = [
  authenticatorVerifyCase(
    "authing_unit_test",
    "the pinned test/core/authing.test.ts response, verified against the agent key",
    {
      method: "GET",
      path: "/identifiers/aid1",
      headers: responseHeaders(),
      verificationKey: RESPONSE_KEY,
    },
  ),
  authenticatorVerifyCase("wrong_path", "the same response verified against another path fails", {
    method: "GET",
    path: "/identifiers/aid2",
    headers: responseHeaders(),
    verificationKey: RESPONSE_KEY,
  }),
  authenticatorVerifyCase("wrong_method", "the same response verified against another method fails", {
    method: "POST",
    path: "/identifiers/aid1",
    headers: responseHeaders(),
    verificationKey: RESPONSE_KEY,
  }),
];

const desiginputCases = [
  {
    name: "unit_test",
    note: "the pinned test/core/httping.test.ts parse case",
    value:
      'sig0=("signify-resource" "@method" "@path" "signify-timestamp");created=1609459200;keyid="EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3";alg="ed25519"',
  },
  {
    name: "every_parameter",
    note: "all six parameters present",
    value:
      'signify=("@method" "@path");created=1609459200;expires=1609545600;nonce="abc";keyid="DN54yRad_BTqgZYUSi_NthRBQrxSnqQdJXWI5UHcGOQt";context="keria";alg="ed25519"',
  },
  {
    name: "two_entries",
    note: "a dictionary with two labelled inputs, which the client never emits but the parser accepts",
    value:
      'signify=("@method");created=1609459200, other=("@path");created=1609459201',
  },
].map((entry) => ({ ...entry, parsed: desiginput(entry.value).map(describeInputage) }));

// The exact spelling `serializeDictionary` gives a two-entry dictionary, which fixes the separator
// between labelled inputs.
const twoEntryDictionary = serializeDictionary(
  new Map([
    ["signify", [[["@method", new Map()]], new Map([["created", 1609459200]])]],
    ["other", [[["@path", new Map()]], new Map([["created", 1609459201]])]],
  ]),
);

const missingHeaderSign = (() => {
  const recorder = recordingSigner(signer);
  const [header] = siginput(recorder.signer, {
    name: "signify",
    method: "GET",
    path: "/x",
    headers: requestHeaders(),
    fields: ["@method", "@path", "signify-resource", "x-absent"],
    alg: "ed25519",
    keyid: KEYID,
  });
  return { base: recorder.captured.base, header: header.get(HEADER_SIG_INPUT) };
})();

const unknownDerivedSign = (() => {
  const recorder = recordingSigner(signer);
  const [header] = siginput(recorder.signer, {
    name: "signify",
    method: "GET",
    path: "/x",
    headers: requestHeaders(),
    fields: ["@method", "@authority", "@query", "@path"],
    alg: "ed25519",
    keyid: KEYID,
  });
  return { base: recorder.captured.base, header: header.get(HEADER_SIG_INPUT) };
})();

const unknownDerivedVerify = authenticatorVerifyCase(
  "unknown_derived_component",
  "a response covering @authority: the field is listed but contributes nothing to the base",
  {
    method: "GET",
    path: "/identifiers/aid1",
    headers: responseHeaders({
      signatureInput: [
        'signify=("@method" "@authority" "@path")',
        "created=1684715820",
        'alg="ed25519"',
      ].join(";"),
    }),
    verificationKey: RESPONSE_KEY,
  },
);

const missingHeaderVerify = authenticatorVerifyCase(
  "missing_covered_header",
  "a response covering a header it does not carry: the item is skipped but the field stays listed",
  {
    method: "GET",
    path: "/identifiers/aid1",
    headers: responseHeaders({
      signatureInput: [
        'signify=("@method" "@path" "x-absent")',
        "created=1684715820",
        'alg="ed25519"',
      ].join(";"),
    }),
    verificationKey: RESPONSE_KEY,
  },
);

const escapedParameter = (() => {
  const recorder = recordingSigner(signer);
  const [header] = siginput(recorder.signer, {
    name: "signify",
    method: "GET",
    path: "/x",
    headers: requestHeaders(),
    fields: ["@method", "@path"],
    keyid: 'a"b\\c',
    alg: "ed25519",
  });
  return { base: recorder.captured.base, header: header.get(HEADER_SIG_INPUT) };
})();

const semicolonParameter = (() => {
  const recorder = recordingSigner(signer);
  const [header] = siginput(recorder.signer, {
    name: "signify",
    method: "GET",
    path: "/x",
    headers: requestHeaders(),
    fields: ["@method", "@path"],
    keyid: "a;alg=forged",
    alg: "ed25519",
  });
  return { base: recorder.captured.base, header: header.get(HEADER_SIG_INPUT) };
})();

const injectedPath = (() => {
  const recorder = recordingSigner(signer);
  const [header] = siginput(recorder.signer, {
    name: "signify",
    method: "GET",
    path: '/a\n"@method": DELETE',
    headers: requestHeaders(),
    fields: ["@path", "@method"],
    alg: "ed25519",
    keyid: KEYID,
  });
  return { base: recorder.captured.base, header: header.get(HEADER_SIG_INPUT) };
})();

const emptyFields = (() => {
  const recorder = recordingSigner(signer);
  const [header] = siginput(recorder.signer, {
    name: "signify",
    method: "GET",
    path: "/x",
    headers: requestHeaders(),
    fields: [],
    alg: "ed25519",
    keyid: KEYID,
  });
  return { base: recorder.captured.base, header: header.get(HEADER_SIG_INPUT) };
})();

const caseSensitiveField = (() => {
  const recorder = recordingSigner(signer);
  const [header] = siginput(recorder.signer, {
    name: "signify",
    method: "GET",
    path: "/x",
    headers: requestHeaders(),
    fields: ["SIGNIFY-RESOURCE"],
    alg: "ed25519",
    keyid: KEYID,
  });
  return { base: recorder.captured.base, header: header.get(HEADER_SIG_INPUT) };
})();

const quirks = {
  created_defaults_to_the_system_clock: {
    frozen_created: 1609459200,
    frozen_at: FROZEN_ISO,
    note: "siginput calls nowUTC(), which is new Date(), so a message and its signature depend on when they were built; the pinned unit tests freeze it with vitest and this generator freezes the global Date to the same instant",
    rust_decision: "created is a required parameter, as the reply timestamp became in Roadmap 3.6, so a protocol crate never reads the clock",
  },
  an_absent_covered_header_is_dropped: {
    signing_base: missingHeaderSign.base,
    signing_header: missingHeaderSign.header,
    verifying_base: missingHeaderVerify.signature_base,
    verifying_fields: 'signify=("@method" "@path" "x-absent")',
    note: "on the signing side an absent header is dropped from the base and from the covered list, so the caller silently gets a weaker signature than it asked for; on the verifying side the field stays listed and only the item disappears, so the base no longer matches what any signer produced",
    rust_error_category: "MissingCoveredHeader",
  },
  an_unknown_derived_component_covers_nothing: {
    signing_base: unknownDerivedSign.base,
    signing_header: unknownDerivedSign.header,
    verifying_base: unknownDerivedVerify.signature_base,
    verifying_threw: unknownDerivedVerify.threw,
    note: "only @method and @path are implemented; any other @-component falls through the switch, so on the verifying side the covered list advertises @authority while the base commits to nothing for it",
    rust_error_category: "UnknownDerivedComponent",
  },
  a_parameter_is_escaped_in_the_header_but_not_in_the_base: {
    base: escapedParameter.base,
    header: escapedParameter.header,
    note: "serializeDictionary escapes the quote and backslash of a string parameter while the signature base interpolates the raw text, so the header and the bytes actually signed disagree about the key identifier",
    rust_error_category: "InvalidFieldText",
  },
  a_parameter_containing_a_semicolon_forges_a_parameter: {
    base: semicolonParameter.base,
    header: semicolonParameter.header,
    note: "the base joins parameters with ';', so a keyid containing one adds a parameter to the signed bytes that the header never carried",
    rust_error_category: "InvalidFieldText",
  },
  a_path_containing_a_newline_forges_a_line: {
    base: injectedPath.base,
    header: injectedPath.header,
    note: "the base joins items with '\\n' and the path is interpolated unvalidated, so a path carrying a newline adds a whole forged component line to the signed bytes",
    rust_error_category: "InvalidRequestPath",
  },
  an_empty_covered_list_is_accepted: {
    base: emptyFields.base,
    header: emptyFields.header,
    note: "a signature covering no component at all is emitted and parsed, binding neither method, path, nor any header",
    rust_error_category: "NoComponents",
  },
  field_names_keep_their_case: {
    base: caseSensitiveField.base,
    header: caseSensitiveField.header,
    note: "the covered list and the base carry the field name exactly as the caller wrote it while the header lookup is case-insensitive, so SIGNIFY-RESOURCE reads the Signify-Resource header and commits to the upper-case spelling; keripy lowercases the name instead, so a mixed-case covered list does not interoperate",
    rust_decision: "the name is preserved verbatim, matching signify-ts, and default_components() uses the lower-case spellings Authenticater.DefaultFields already uses",
  },
  duplicate_headers_are_joined: {
    joined: new Headers([
      ["X-Repeat", "1"],
      ["X-Repeat", "2"],
    ]).get("x-repeat"),
    note: "the fetch Headers collection joins repeated fields with a comma and a space, so a duplicated covered header silently changes the signature base",
    rust_error_category: "DuplicateHeader",
  },
  desiginput_requires_created: {
    ...rejected(() => desiginput('signify=("@method");alg="ed25519"')),
    note: "created is the only required parameter",
    rust_error_category: "MissingCreated",
  },
  desiginput_rejects_a_malformed_dictionary: {
    ...rejected(() => desiginput("signify=(")),
    note: "the structured-fields parser raises its own error type for a malformed value",
    rust_error_category: "MalformedSignatureInput",
  },
  a_duplicate_label_replaces_the_earlier_input: {
    parsed: desiginput('signify=("@method");created=1, signify=("@path");created=2').map(describeInputage),
    note: "an RFC 8941 dictionary keeps the last member with a given key, so a second signify input silently discards the first",
    rust_error_category: "DuplicateLabel",
  },
  verify_hardcodes_the_signify_label: {
    ...(() => {
      const headers = responseHeaders({
        signatureInput: [
          'sig0=("signify-resource" "@method" "@path" "signify-timestamp")',
          "created=1684715820",
          'alg="ed25519"',
        ].join(";"),
      });
      const authenticator = new Authenticater(signer, new Verfer({ qb64: RESPONSE_KEY }));
      return rejected(() => authenticator.verify(headers, "GET", "/identifiers/aid1"));
    })(),
    note: "verify filters the parsed inputs to the literal name 'signify', so a correctly signed response under any other label is reported unverified rather than checked",
    rust_decision: "the expected label is a constructor parameter",
  },
  verify_reads_only_the_first_signage: {
    ...(() => {
      const headers = responseHeaders({
        signature: `indexed="?0";x="${RESPONSE_SIGNATURE}",indexed="?0";signify="${RESPONSE_SIGNATURE}"`,
      });
      const authenticator = new Authenticater(signer, new Verfer({ qb64: RESPONSE_KEY }));
      return rejected(() => authenticator.verify(headers, "GET", "/identifiers/aid1"));
    })(),
    note: "designature returns every signage but verify indexes [0], so a signature carried in a later signage is invisible",
    rust_decision: "every signage is searched and exactly one marker must carry the expected label",
  },
  verify_is_false_for_a_missing_header_and_throws_for_a_bad_signature: {
    missing_signature_input: rejected(() => {
      const headers = responseHeaders();
      headers.delete(HEADER_SIG_INPUT);
      return new Authenticater(signer, new Verfer({ qb64: RESPONSE_KEY })).verify(headers, "GET", "/identifiers/aid1");
    }),
    missing_signature: rejected(() => {
      const headers = responseHeaders();
      headers.delete("Signature");
      return new Authenticater(signer, new Verfer({ qb64: RESPONSE_KEY })).verify(headers, "GET", "/identifiers/aid1");
    }),
    bad_signature: rejected(() =>
      new Authenticater(signer, new Verfer({ qb64: RESPONSE_KEY })).verify(
        responseHeaders(),
        "GET",
        "/identifiers/wrong",
      ),
    ),
    note: "a missing header returns false while an invalid signature throws, so a caller has to handle two failure shapes for one question",
    rust_decision: "verification returns Result<SignatureInput, AuthenticationError> with a distinct variant per failure",
  },
};

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-19",
  sources: [
    "src/keri/core/httping.ts",
    "src/keri/core/authing.ts",
    "test/core/httping.test.ts",
    "test/core/authing.test.ts",
  ],
  clock: {
    frozen_at: FROZEN_ISO,
    created: Math.floor(FROZEN_MS / 1000),
    note: "the global Date is frozen so `created` is deterministic; the pinned unit tests freeze `nowUTC` to the same instant",
  },
  signer: {
    salt: SALT,
    tier: "low",
    temporary_profile: false,
    path: "",
    transferable: true,
    verification_key: KEYID,
  },
  header_names: {
    signature_input: HEADER_SIG_INPUT,
    signature: "Signature",
    signify_timestamp: HEADER_SIG_TIME,
  },
  // `Authenticater.DefaultFields`, which is what every KERIA request covers.
  default_fields: Authenticater.DefaultFields,
  normalize_trims: {
    input: "  padded  ",
    output: normalize("  padded  "),
  },
  siginput_cases: siginputCases,
  authenticator_sign_cases: authenticatorSignCases,
  authenticator_verify_cases: authenticatorVerifyCases,
  desiginput_cases: desiginputCases,
  two_entry_dictionary: twoEntryDictionary,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/http-authing/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("http-authing fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}

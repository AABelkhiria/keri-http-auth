// Generates and checks Signature-header vectors from the pinned signify-ts.
import { readFileSync, writeFileSync } from "node:fs";

import { b } from "./node_modules/signify-ts/dist/keri/core/core.js";
import { designature, signature, Signage, FALSY, TRUTHY } from "./node_modules/signify-ts/dist/keri/end/ending.js";
import { Cigar } from "./node_modules/signify-ts/dist/keri/core/cigar.js";
import { Siger } from "./node_modules/signify-ts/dist/keri/core/siger.js";
import { MtrDex } from "./node_modules/signify-ts/dist/keri/core/matter.js";
import { Salter, Tier } from "./node_modules/signify-ts/dist/keri/core/salter.js";
import libsodium from "./node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";
import { referenceSha } from "./reference.mjs";

await libsodium.ready;


// Exactly the provenance the pinned `test/end/ending.test.ts` uses: a raw 16-byte salt, three
// derivation paths, the low tier, and the temporary Argon2 profile (`temp`).
const SALT = "0123456789abcdef";
const NAMES = ["Hilga00", "Hilga01", "Hilga02"];
const TEXT = JSON.stringify({
  seid: "BA89hKezugU2LFKiFVbitoHAxXqJh6HQ8Rn9tH7fxd68",
  name: "wit0",
  dts: "2021-01-01T00:00:00.000000+00:00",
  scheme: "http",
  host: "localhost",
  port: 8080,
  path: "/witness",
});
// `Hab.pre` from the keripy test the upstream suite mirrors.
const PREFIX = "EGqHykT1gVyuWxsVW6LUUsz_KtLJGYMi_SrohInwvjC-";

const salter = new Salter({ raw: b(SALT) });
const signers = NAMES.map((name) => salter.signer(MtrDex.Ed25519_Seed, true, name, Tier.low, true));
const text = b(TEXT);
const sigers = signers.map((signer, index) => signer.sign(text, index));
const cigars = signers.map((signer) => signer.sign(text));

function describeMarkers(signage) {
  const entries =
    signage.markers instanceof Map ? [...signage.markers.entries()] : signage.markers.map((m, i) => [null, m]);
  return entries.map(([tag, marker]) => ({
    tag,
    value: typeof marker === "string" ? marker : marker.qb64,
    kind: marker instanceof Siger ? "indexed" : marker instanceof Cigar ? "unindexed" : "text",
    // An unindexed marker is tagged with its own key, so a rebuilder needs it even when the
    // reference took the markers as a bare list and wrote no tag of its own.
    verification_key: marker instanceof Cigar ? marker.verfer.qb64 : null,
  }));
}

function headerCase(name, signages, note) {
  const value = signature(signages).get("Signature");
  // Reverse direction: the reference reads the exact bytes back.
  const reparsed = designature(value).map((signage) => ({
    indexed: signage.indexed,
    signer: signage.signer ?? null,
    ordinal: signage.ordinal ?? null,
    digest: signage.digest ?? null,
    kind: signage.kind ?? null,
    markers: [...signage.markers.entries()].map(([tag, marker]) => ({
      tag,
      value: typeof marker === "string" ? marker : marker.qb64,
      kind: marker instanceof Siger ? "indexed" : marker instanceof Cigar ? "unindexed" : "text",
    })),
  }));
  return {
    name,
    note,
    signages: signages.map((signage) => ({
      indexed: signage.indexed ?? null,
      signer: signage.signer ?? null,
      ordinal: signage.ordinal ?? null,
      digest: signage.digest ?? null,
      kind: signage.kind ?? null,
      markers: describeMarkers(signage),
    })),
    header: value,
    header_length: value.length,
    reparsed,
  };
}

const namedSigers = new Map(sigers.map((siger, index) => [`siger${index}`, siger]));

const cases = [
  headerCase("indexed_default_tags", [new Signage(sigers)], "each marker is tagged with its own signature index"),
  headerCase("named_indexed", [new Signage(namedSigers)], "explicit tags replace the index defaults"),
  headerCase(
    "indexed_cesr_full",
    [new Signage(sigers, true, PREFIX, "0", PREFIX, "CESR")],
    "every parameter present, in the order the reference writes them",
  ),
  headerCase(
    "unindexed_default_tags",
    [new Signage(cigars)],
    "each marker is tagged with the verification key that verifies it",
  ),
  headerCase(
    "combined",
    [new Signage(sigers, true, PREFIX, undefined, undefined, "CESR"), new Signage(cigars, false, PREFIX, undefined, undefined, "CESR")],
    "two signages in one header, comma separated",
  ),
  // The shape `core/authing.ts` actually sends on every request.
  headerCase(
    "authing_single_named_unindexed",
    [new Signage(new Map([["signify", cigars[0]]]), false)],
    "one named unindexed marker, which is what the request signer emits",
  ),
  headerCase(
    "opaque_kind",
    [new Signage(new Map([["x", "1"], ["y", "2"]]), false, undefined, undefined, undefined, "JSON")],
    "a non-CESR kind leaves the marker values uninterpreted",
  ),
];

function rejected(operation) {
  try {
    const value = operation();
    return { threw: false, error_category: null, error_message: null, value: typeof value === "string" ? value : null };
  } catch (error) {
    return {
      threw: true,
      error_category: error?.constructor?.name ?? "Unknown",
      error_message: String(error?.message ?? error),
      value: null,
    };
  }
}

const emit = (signages) => signature(signages).get("Signature");
const parseShape = (value) =>
  designature(value).map((signage) => ({
    indexed: signage.indexed,
    signer: signage.signer ?? null,
    kind: signage.kind ?? null,
    markers: [...signage.markers.entries()].map(([tag, marker]) => ({
      tag,
      value: typeof marker === "string" ? marker : marker.qb64,
    })),
  }));

const quirks = {
  a_tag_forges_header_fields: {
    header: emit([new Signage(new Map([['a";b="c', sigers[0]]]), true)]),
    note: "tags are interpolated unescaped, so a tag carrying the delimiters produces a header whose extra field a parser reads as real",
    rust_error_category: "InvalidFieldText",
  },
  a_value_forges_header_fields: {
    header: emit([new Signage(new Map([["x", 'val";indexed="?0']]), false, undefined, undefined, undefined, "JSON")]),
    note: "values are interpolated unescaped too, so a marker value can inject a second indexed flag into its own signage",
    rust_error_category: "InvalidFieldText",
  },
  only_the_first_space_is_removed: {
    // A second space survives and becomes part of the tag that follows it.
    corrupted_tag: parseShape(`indexed="?1"; 0="${sigers[0].qb64}"; 1="${sigers[1].qb64}"`),
    // When the surviving space precedes `indexed`, the signage loses its required field entirely.
    unparsable: rejected(() =>
      designature(`indexed="?1"; 0="${sigers[0].qb64}", indexed="?0";${cigars[0].verfer.qb64}="${cigars[0].qb64}"`),
    ),
    note: "JavaScript String.replace with a string argument replaces one occurrence, so every space after the first survives: it either becomes part of the following tag or, before `indexed`, hides the required field and the whole header fails; keripy's str.replace removes them all",
    rust_decision: "whitespace around the , and ; separators is skipped, which is what both implementations mean",
  },
  an_item_without_a_value_crashes: {
    ...rejected(() => designature('indexed="?1";garbage')),
    note: "the split produces one element and the code indexes the missing second, so a malformed header raises a TypeError rather than a protocol error",
    rust_error_category: "MalformedItem",
  },
  an_empty_header_crashes: {
    ...rejected(() => designature("")),
    note: "the same dereference, reached by the empty string",
    rust_error_category: "MalformedItem",
  },
  a_value_containing_equals_is_truncated: {
    ...rejected(() => designature('indexed="?1";0="a=b"')),
    note: "split('=', 2) discards the remainder in JavaScript, so the value becomes `a`; Python's maxsplit keeps it, so keripy reads `a=b` -- the two disagree about the same header",
    rust_error_category: "MalformedItem",
  },
  quotes_are_stripped_from_anywhere: {
    ...rejected(() => designature('indexed="?1";0="a"b"c"')),
    note: "replaceAll('\"', '') removes every quote rather than the surrounding pair, silently joining the pieces into abc",
    rust_error_category: "MalformedItem",
  },
  the_indexed_flag_is_true_unless_it_matches_falsy: {
    zero: parseShape(`indexed="0";0="${sigers[0].qb64}"`)[0].indexed,
    garbage: parseShape(`indexed="maybe";0="${sigers[0].qb64}"`)[0].indexed,
    empty: parseShape(`indexed="";0="${sigers[0].qb64}"`)[0].indexed,
    falsy: FALSY.map((entry) => (typeof entry === "string" ? entry : String(entry))),
    truthy: TRUTHY.map((entry) => (typeof entry === "string" ? entry : String(entry))),
    note: "the test is `not in FALSY`, and FALSY's `false` and `0` entries are a boolean and a number that a parsed string can never equal, so indexed=\"0\" is read as true -- the opposite of what it says",
    rust_error_category: "InvalidIndexedFlag",
  },
  a_repeated_tag_drops_a_signature: {
    parsed: parseShape(`indexed="?1";0="${sigers[0].qb64}";0="${sigers[1].qb64}"`),
    note: "items are collected into a Map, so the second silently replaces the first and one signature disappears",
    rust_error_category: "DuplicateField",
  },
  a_marker_tagged_as_a_parameter_disappears: {
    parsed: parseShape(`indexed="?1";signer="${sigers[0].qb64}"`),
    note: "parameters are read out of the same map as the markers, so a marker tagged signer becomes the signer parameter and leaves no marker behind",
    rust_error_category: "ReservedTag",
  },
  an_empty_signage_is_accepted: {
    emitted: emit([new Signage([])]),
    parsed: parseShape('indexed="?1"'),
    note: "a signage with no markers renders and parses, asserting nothing at all",
    rust_error_category: "NoMarkers",
  },
  marker_and_flag_disagreement_throws: {
    indexed_signature_unindexed_flag: rejected(() => emit([new Signage(sigers, false)])),
    unindexed_signature_indexed_flag: rejected(() => emit([new Signage(cigars, true)])),
    unindexed_signature_without_key: rejected(() => emit([new Signage([new Cigar({ qb64: cigars[0].qb64 })])])),
    note: "the flag is a separate argument that can contradict the marker types, and an unindexed marker needs a verfer for its default tag",
    rust_decision: "the flag is derived from the marker variant and an unnamed unindexed marker requires its key, so none of the three states is representable",
  },
};

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-19",
  sources: ["src/keri/end/ending.ts", "test/end/ending.test.ts"],
  signers: {
    salt: SALT,
    tier: "low",
    temporary_profile: true,
    paths: NAMES,
    signed_text: TEXT,
    verification_keys: cigars.map((cigar) => cigar.verfer.qb64),
    indexed_signatures: sigers.map((siger) => siger.qb64),
    unindexed_signatures: cigars.map((cigar) => cigar.qb64),
  },
  prefix: PREFIX,
  cases,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/ending/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("ending fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}

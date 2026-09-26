import { test } from "node:test";
import assert from "node:assert/strict";
import { isFieldFuzzableVerb } from "../src/beat.js";

test("blind field-fuzzers may fire GET and POST (read + long-standing injection surface)", () => {
  for (const m of ["GET", "POST", "get", "post"]) assert.equal(isFieldFuzzableVerb(m), true, `${m} should be fuzzable`);
  assert.equal(isFieldFuzzableVerb(undefined), true, "missing method defaults to GET -> fuzzable");
});

test("blind field-fuzzers must NOT fire un-restorable state-changers (PUT/PATCH/DELETE)", () => {
  for (const m of ["PUT", "PATCH", "DELETE", "put", "patch", "delete"]) {
    assert.equal(isFieldFuzzableVerb(m), false, `${m} must be excluded from blind fuzzing (un-restored writes)`);
  }
});

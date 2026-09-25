import { test } from "node:test";
import assert from "node:assert/strict";
import { classifyField, mapFields, looksLikeLogin, looksLikePasswordChange, extractJwt } from "../src/stateful.js";

test("classifyField: old/new/plain password + username by generic naming", () => {
  assert.equal(classifyField("old_pass"), "old_password");
  assert.equal(classifyField("currentPassword"), "old_password");
  assert.equal(classifyField("new_pass"), "new_password");
  assert.equal(classifyField("confirmPassword"), "new_password");
  assert.equal(classifyField("password"), "password");
  assert.equal(classifyField("pwd"), "password");
  assert.equal(classifyField("username"), "username");
  assert.equal(classifyField("email"), "username");
  assert.equal(classifyField("mobile"), "username");
  assert.equal(classifyField("amount"), null);
});

test("mapFields maps nested envelope leaves by their last segment", () => {
  const fm = mapFields(["data.username", "data.password"]);
  assert.equal(fm.username, "data.username");
  assert.equal(fm.password, "data.password");
  const chg = mapFields(["data.old_pass", "data.new_pass"]);
  assert.equal(chg.old_password, "data.old_pass");
  assert.equal(chg.new_password, "data.new_pass");
});

test("looksLikeLogin: username+password, not a change form, not logout", () => {
  assert.equal(looksLikeLogin({ username: "u", password: "p" }, "http://t/api/login"), true);
  // A change form (has old/new) is NOT a login.
  assert.equal(looksLikeLogin({ username: "u", old_password: "o", new_password: "n" }, "http://t/api/password/change"), false);
  assert.equal(looksLikeLogin({ username: "u", password: "p" }, "http://t/api/logout"), false);
});

test("looksLikePasswordChange: new_password + (old_password OR change-verb URL)", () => {
  assert.equal(looksLikePasswordChange({ old_password: "o", new_password: "n" }, "http://t/api/password/change"), true);
  // change-verb URL without an explicit old field still counts (new_password present).
  assert.equal(looksLikePasswordChange({ new_password: "n" }, "http://t/api/changePassword"), true);
  // a plain login is not a change.
  assert.equal(looksLikePasswordChange({ username: "u", password: "p" }, "http://t/api/login"), false);
});

test("extractJwt: pulls the longest JWT-shaped token from a body, null when absent", () => {
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYm9iIn0.abcDEF123456_-";
  assert.equal(extractJwt(`{"token":"${jwt}","code":"LGN002"}`), jwt);
  // failed login: an error body with no token.
  assert.equal(extractJwt(`{"code":"LGN003","message":"invalid credentials"}`), null);
  assert.equal(extractJwt(null), null);
  assert.equal(extractJwt(""), null);
});

test("extractJwt marker is a genuine pre->post discriminator: absent in a failed login", () => {
  const success = `{"token":"eyJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjQyfQ.SIGSIGSIGSIG"}`;
  const failure = `{"code":"LGN003"}`;
  const jwt = extractJwt(success)!;
  assert.ok(jwt && !failure.includes(jwt), "the extracted JWT must be absent in the failed-login body");
  assert.ok(success.includes(jwt), "the extracted JWT must be present in the success body");
});

import { evaluate } from "../src/axiom.js";
import type { HttpCapture } from "../src/tools.js";

function cap(status: number, body: string): HttpCapture {
  return {
    request: { method: "POST", url: "http://t/api/login", headers: {}, body: null },
    response: { status, headers: {}, body },
    artifact: { hash: "x", path: "x", bytes: 0 } as unknown as HttpCapture["artifact"],
    ms: 1,
  };
}

test("F-24 proof shape: appeared:<jwt> CONFIRMS when post-change login succeeds", () => {
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjF9.SIGSIGSIGSIGSIG";
  const c0 = cap(401, `{"code":"LGN003","message":"invalid"}`);          // pre: login with P2 fails
  const act = cap(200, `{"code":"PSW008","message":"password updated"}`); // change with wrong-old commits
  const c2 = cap(200, `{"token":"${jwt}","code":"LGN002"}`);              // post: login with P2 succeeds
  const v = evaluate({ statement: "s", type: "state_changed", expression: `appeared:${jwt}` }, c2, null, { captures: [c0, act, c2] });
  assert.equal(v.status, "CONFIRMED", v.reason);
});

test("F-24 proof shape: NO finding when the change is correctly rejected (post login still fails)", () => {
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjF9.SIGSIGSIGSIGSIG";
  const c0 = cap(401, `{"code":"LGN003"}`);
  const act = cap(400, `{"code":"PSW009","message":"old password incorrect"}`); // rejected
  const c2 = cap(401, `{"code":"LGN003"}`);  // login with P2 still fails -> no JWT extracted upstream, but assert Axiom too
  const v = evaluate({ statement: "s", type: "state_changed", expression: `appeared:${jwt}` }, c2, null, { captures: [c0, act, c2] });
  assert.notEqual(v.status, "CONFIRMED");
});

test("F-24 proof shape: FALSE_POSITIVE guard if the marker was already present pre", () => {
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjF9.SIGSIGSIGSIGSIG";
  const c0 = cap(200, `{"token":"${jwt}"}`);  // P2 already worked pre (shouldn't happen; guard)
  const act = cap(200, `{"code":"PSW008"}`);
  const c2 = cap(200, `{"token":"${jwt}"}`);
  const v = evaluate({ statement: "s", type: "state_changed", expression: `appeared:${jwt}` }, c2, null, { captures: [c0, act, c2] });
  assert.equal(v.status, "FALSE_POSITIVE", v.reason);
});

import { classifyContactField, extractAssignedId } from "../src/stateful.js";

test("classifyContactField: email/mobile by generic naming", () => {
  assert.equal(classifyContactField("email"), "email");
  assert.equal(classifyContactField("mobile"), "mobile");
  assert.equal(classifyContactField("phone"), "mobile");
  assert.equal(classifyContactField("firstname"), null);
});

test("extractAssignedId: named id field wins, else an assigned-id-shaped value", () => {
  assert.equal(extractAssignedId(`{"status":"Success","data":{"userId":"BNK64092","refNo":"174543797617147"}}`), "BNK64092");
  assert.equal(extractAssignedId(`{"data":{"foo":"bar","account":"ACC12345"}}`), "ACC12345"); // id-shaped fallback
  assert.equal(extractAssignedId(`{"status":"Failed","data":{}}`), null);
  assert.equal(extractAssignedId(null), null);
});

import { findDeviceObject, graftDevice } from "../src/stateful.js";

test("findDeviceObject + graftDevice: carry a known-good device block across bodies", () => {
  const good = `{"requestBody":{"device":{"deviceid":"D1","os":"android"},"data":{"x":"1"}}}`;
  const dev = findDeviceObject(JSON.parse(good));
  assert.deepEqual(dev, { deviceid: "D1", os: "android" });
  const stale = `{"requestBody":{"device":{"deviceid":"D9","os":"windows"},"data":{"userid":"U"}}}`;
  const fixed = graftDevice(stale, dev);
  assert.ok(fixed.includes('"os":"android"') && !fixed.includes('"os":"windows"'));
  assert.ok(fixed.includes('"userid":"U"'), "non-device data is preserved");
});

import { buildXxeXml } from "../src/stateful.js";

test("buildXxeXml: elements named after the app's fields, entity in non-email fields", () => {
  const xml = buildXxeXml(["data.name", "data.email", "data.message"]);
  assert.ok(xml.includes("<!ENTITY xxe SYSTEM \"file:///etc/passwd\">"));
  assert.ok(xml.includes("<name>&xxe;</name>"), "entity injected into name");
  assert.ok(xml.includes("<message>&xxe;</message>"), "entity injected into message");
  assert.ok(xml.includes("<email>sahwxxe@example.test</email>"), "email gets a benign value");
  assert.ok(!xml.includes("<x>"), "no generic placeholder element");
});

test("F-13 deriver: CONFIRMED when OTP issued from a single identity field, no secondary factor", () => {
  const v = evaluate(
    { statement: "s", type: "derived", expression: "no_secondary_factor_before_otp" },
    cap(200, ""), null,
    { derivedInput: { requestFieldNames: ["data.userid", "data.otp_type"], exploitResponse: '{"status":"Success","status_code":"OTP001","data":{"response":"enc=="}}', controlResponse: '{"status":"Failed","status_code":"PSW002"}' } },
  );
  assert.equal(v.status, "CONFIRMED", v.reason);
});

test("F-13 deriver: FALSE_POSITIVE when a secondary-factor field is present", () => {
  const v = evaluate(
    { statement: "s", type: "derived", expression: "no_secondary_factor_before_otp" },
    cap(200, ""), null,
    { derivedInput: { requestFieldNames: ["data.userid", "data.dob", "data.otp_type"], exploitResponse: '{"status":"Success"}', controlResponse: '{"status":"Failed"}' } },
  );
  assert.equal(v.status, "FALSE_POSITIVE", v.reason);
});

test("F-13 deriver: FALSE_POSITIVE when exploit and control responses are identical (issuance not shown)", () => {
  const same = '{"status":"Success","status_code":"OTP001"}';
  const v = evaluate(
    { statement: "s", type: "derived", expression: "no_secondary_factor_before_otp" },
    cap(200, ""), null,
    { derivedInput: { requestFieldNames: ["data.userid", "data.otp_type"], exploitResponse: same, controlResponse: same } },
  );
  assert.equal(v.status, "FALSE_POSITIVE", v.reason);
});

import { parseAesCbcParams } from "../src/stateful.js";

test("parseAesCbcParams: recovers key+iv from a createDecipheriv call site", () => {
  const js = 'function(e,a,t,n){var r=xe.a.createDecipheriv(a,t,n);return r}(e.data,"AES-256-CBC","9bbc0d79e686e847bc305c9bd4cc2ea6","0123456789abcdef")';
  const p = parseAesCbcParams(js);
  assert.equal(p?.key, "9bbc0d79e686e847bc305c9bd4cc2ea6");
  assert.equal(p?.iv, "0123456789abcdef");
  assert.equal(parseAesCbcParams("no crypto here"), null);
});

test("F-25 proof shape: field balance b0->b1 CONFIRMS with restoration proof", () => {
  const before = cap(200, '{"status":"Success","data":{"accountBalance":"711550.18"}}');
  const pay = cap(200, '{"status":"Success","status_code":"BNF015","data":{"updated_balance":716550.18}}');
  const after = cap(200, '{"status":"Success","data":{"accountBalance":"716550.18"}}');
  const restoreProof = cap(200, '{"status":"Success","status_code":"BNF015"}');
  const v = evaluate(
    { statement: "s", type: "state_changed", expression: "field:data.accountBalance;from:711550.18;to:716550.18" },
    after, null, { captures: [before, pay, after], restoration: { required: true, performed: true, proof: restoreProof } },
  );
  assert.equal(v.status, "CONFIRMED", v.reason);
});

test("F-25 proof shape: required restoration WITHOUT proof downgrades to NEEDS_REVIEW", () => {
  const before = cap(200, '{"data":{"accountBalance":"100.00"}}');
  const pay = cap(200, '{"status_code":"BNF015"}');
  const after = cap(200, '{"data":{"accountBalance":"200.00"}}');
  const v = evaluate(
    { statement: "s", type: "state_changed", expression: "field:data.accountBalance;from:100.00;to:200.00" },
    after, null, { captures: [before, pay, after], restoration: { required: true, performed: false } },
  );
  assert.equal(v.status, "NEEDS_REVIEW", v.reason);
});

test("parseAesCbcParams: also handles PHP openssl_encrypt (key,options,iv non-consecutive)", () => {
  const php = `openssl_encrypt($otp, 'aes-256-cbc', "9bbc0d79e686e847bc305c9bd4cc2ea6", $options=OPENSSL_RAW_DATA, "0123456789abcdef")`;
  const p = parseAesCbcParams(php);
  assert.equal(p?.key, "9bbc0d79e686e847bc305c9bd4cc2ea6");
  assert.equal(p?.iv, "0123456789abcdef");
});

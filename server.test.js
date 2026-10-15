
const test = require("node:test");
const assert = require("node:assert/strict");

const {
  hashPassword,
  verifyPassword,
  validInput
} = require("./server");

test("password is stored as a hash", () => {
  const password = "my-long-test-password";
  const record = hashPassword(password);

  assert.notEqual(record.hash, password);
  assert.equal(verifyPassword(password, record), true);
  assert.equal(verifyPassword("wrong-password", record), false);
});

test("validates username and password", () => {
  assert.equal(
    validInput("student01", "long-test-password"),
    true
  );

  assert.equal(validInput("x", "short"), false);
  assert.equal(validInput("bad name", "long-test-password"), false);
});

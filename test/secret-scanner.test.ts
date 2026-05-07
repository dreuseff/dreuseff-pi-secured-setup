/**
 * Unit tests for lib/secret-scanner.ts
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
	isPlaceholder,
	isCommentLine,
	redactString,
	walkAndRedact,
} from "../lib/secret-scanner.js";

describe("isPlaceholder", () => {
	it("detects YOUR_ prefix", () => {
		assert.equal(isPlaceholder("YOUR_API_KEY"), true);
	});

	it("detects <placeholder>", () => {
		assert.equal(isPlaceholder("<insert-key-here>"), true);
	});

	it("detects xxx placeholder", () => {
		assert.equal(isPlaceholder("xxxxxx"), true);
	});

	it("detects *** placeholder", () => {
		assert.equal(isPlaceholder("***"), true);
	});

	it("detects REPLACE_ prefix", () => {
		assert.equal(isPlaceholder("REPLACE_WITH_KEY"), true);
	});

	it("detects example prefix", () => {
		assert.equal(isPlaceholder("example_key_value"), true);
	});

	it("does not flag real values", () => {
		assert.equal(isPlaceholder("AKIAIOSFODNN7EXAMPLE"), false);
		assert.equal(isPlaceholder("sk-ant-api03-real-key"), false);
	});
});

describe("isCommentLine", () => {
	it("detects # comments", () => {
		assert.equal(isCommentLine("# AWS_KEY=secret"), true);
	});

	it("detects // comments", () => {
		assert.equal(isCommentLine("// const key = 'secret'"), true);
	});

	it("detects -- comments", () => {
		assert.equal(isCommentLine("-- password: secret"), true);
	});

	it("detects /* comments", () => {
		assert.equal(isCommentLine("/* secret stuff */"), true);
	});

	it("does not flag non-comments", () => {
		assert.equal(isCommentLine('password = "secret"'), false);
		assert.equal(isCommentLine("const x = 1"), false);
	});

	it("handles leading whitespace", () => {
		assert.equal(isCommentLine("  # indented comment"), true);
	});
});

describe("redactString", () => {
	it("redacts AWS access keys", () => {
		const { result, redactions } = redactString("key=AKIAIOSFODNN7EXAMPLE");
		assert.ok(result.includes("***REDACTED:aws-access-key***"));
		assert.equal(redactions.length, 1);
		assert.equal(redactions[0].patternName, "aws-access-key");
	});

	it("redacts Anthropic keys", () => {
		const { result } = redactString("ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz");
		assert.ok(result.includes("***REDACTED:anthropic-key***"));
	});

	it("redacts private key headers", () => {
		const { result } = redactString("-----BEGIN RSA PRIVATE KEY-----");
		assert.ok(result.includes("***REDACTED:private-key***"));
	});

	it("redacts GitHub tokens", () => {
		const { result } = redactString("token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789a");
		assert.ok(result.includes("***REDACTED:github-token***"));
	});

	it("redacts DB connection strings", () => {
		const { result } = redactString("DATABASE_URL=postgres://user:pass@host:5432/db");
		assert.ok(result.includes("***REDACTED:db-connection***"));
	});

	it("redacts Slack tokens", () => {
		const { result } = redactString("SLACK_TOKEN=xoxb-XXXXXXXXXX-aaaaaaaaaaaaaaaa");
		assert.ok(result.includes("***REDACTED:slack-token***"));
	});

	it("redacts passwords in config", () => {
		const { result } = redactString('password="supersecret123"');
		assert.ok(result.includes("***REDACTED:password***"));
	});

	it("skips comment lines entirely", () => {
		const { result, redactions } = redactString("# password=\"supersecret123\"");
		assert.equal(redactions.length, 0);
		assert.equal(result, "# password=\"supersecret123\"");
	});

	it("does not redact normal strings", () => {
		const { result, redactions } = redactString("just a normal log line");
		assert.equal(redactions.length, 0);
		assert.equal(result, "just a normal log line");
	});

	it("handles multiple secrets in one string", () => {
		const { result, redactions } = redactString(
			"aws=AKIAIOSFODNN7EXAMPLE db=postgres://user:pass@host/db",
		);
		assert.ok(result.includes("***REDACTED:aws-access-key***"));
		assert.ok(result.includes("***REDACTED:db-connection***"));
		assert.ok(redactions.length >= 2);
	});

	it("preserves surrounding text", () => {
		const { result } = redactString("The key is AKIAIOSFODNN7EXAMPLE in production");
		assert.ok(result.startsWith("The key is "));
		assert.ok(result.includes("in production"));
	});
});

describe("walkAndRedact", () => {
	it("redacts secrets in nested objects", () => {
		const payload = {
			messages: [
				{ role: "user", content: "Here is my key: AKIAIOSFODNN7EXAMPLE" },
			],
		};
		const redactions: unknown[] = [];
		walkAndRedact(payload, redactions);
		assert.ok(redactions.length > 0);
		assert.ok(
			(payload.messages[0] as { content: string }).content.includes("***REDACTED:aws-access-key***"),
		);
	});

	it("redacts secrets in arrays", () => {
		const arr = ["normal", "AKIAIOSFODNN7EXAMPLE", "also normal"];
		const redactions: unknown[] = [];
		walkAndRedact(arr, redactions);
		assert.equal(redactions.length, 1);
		assert.ok(arr[1].includes("***REDACTED:aws-access-key***"));
	});

	it("handles non-string primitives", () => {
		const obj = { num: 42, bool: true, nil: null };
		const redactions: unknown[] = [];
		walkAndRedact(obj, redactions);
		assert.equal(redactions.length, 0);
		assert.equal(obj.num, 42);
		assert.equal(obj.bool, true);
		assert.equal(obj.nil, null);
	});

	it("respects depth limit", () => {
		const deep = { a: { b: { c: { d: { e: "AKIAIOSFODNN7EXAMPLE" } } } } };
		const redactions: unknown[] = [];
		walkAndRedact(deep, redactions, 0);
		// Should still work — depth 5 is well within limit of 50
		assert.ok(redactions.length > 0);
	});
});

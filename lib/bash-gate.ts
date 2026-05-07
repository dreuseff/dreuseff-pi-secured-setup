/**
 * Bash command classification — pure function.
 *
 * Classifies bash commands into SAFE / MODERATE / DANGEROUS / EXTERNAL
 * categories based on regex rules merged from defaults → machine → project.
 *
 * DANGEROUS → confirm
 * EXTERNAL  → confirm
 * MODERATE  → allow (logged)
 * SAFE      → allow (logged)
 * Unknown   → confirm
 *
 * Handles pipes by classifying each component and taking the most dangerous.
 */
import type { Config } from "./config.js";
import type { GuardVerdict } from "./boundary.js";

type CommandCategory = "safe" | "moderate" | "dangerous" | "external";

const CATEGORY_PRIORITY: CommandCategory[] = ["dangerous", "external", "moderate", "safe"];

/**
 * Classify a single command segment against the rule patterns.
 */
export function classifySegment(command: string, rules: Record<CommandCategory, string[]>): CommandCategory | null {
	for (const category of CATEGORY_PRIORITY) {
		const patterns = rules[category];
		for (const pattern of patterns) {
			try {
				const regex = new RegExp(pattern, "i");
				if (regex.test(command)) {
					return category;
				}
			} catch {
				// Skip invalid regex patterns
			}
		}
	}
	return null;
}

/**
 * Split a command string by pipes into individual segments.
 * Also extracts subshell commands from $(...) expressions.
 */
export function splitCommand(command: string): string[] {
	const segments: string[] = [];

	// Split by pipes (simple approach — doesn't handle quoted pipes)
	const pipeParts = command.split("|").map((s) => s.trim());
	for (const part of pipeParts) {
		segments.push(part);

		// Extract subshell commands from $(...)
		const subshellRegex = /\$\(([^)]+)\)/g;
		let match: RegExpExecArray | null;
		while ((match = subshellRegex.exec(part)) !== null) {
			segments.push(match[1].trim());
		}
	}

	return segments;
}

/**
 * Classify a bash command string.
 *
 * @param command — The full bash command string
 * @param config  — Merged runtime configuration
 * @returns GuardVerdict with an extra `category` in details for audit
 */
export function classifyCommand(
	command: string,
	config: Config,
): GuardVerdict & { category?: CommandCategory } {
	const segments = splitCommand(command);

	let highestCategory: CommandCategory | null = null;
	const rules = config.commandRules;

	for (const segment of segments) {
		if (!segment) continue;
		const cat = classifySegment(segment, rules);
		if (cat !== null) {
			if (highestCategory === null) {
				highestCategory = cat;
			} else if (
				CATEGORY_PRIORITY.indexOf(cat) < CATEGORY_PRIORITY.indexOf(highestCategory)
			) {
				highestCategory = cat;
			}
		}
	}

	// No known pattern matched → unknown command → confirm
	if (highestCategory === null) {
		return {
			action: "confirm",
			message: `Unknown command — allow execution?\n\n  ${command}\n\nThis command doesn't match any known safety classification.`,
			category: undefined,
		};
	}

	// SAFE and MODERATE are auto-approved
	if (highestCategory === "safe") {
		return { action: "allow", category: "safe" };
	}

	if (highestCategory === "moderate") {
		return { action: "allow", category: "moderate" };
	}

	// DANGEROUS and EXTERNAL require confirmation
	const label = highestCategory === "dangerous" ? "Dangerous" : "External";
	return {
		action: "confirm",
		message: `⚠️ ${label} command — allow execution?\n\n  ${command}\n\nClassification: ${highestCategory.toUpperCase()}`,
		category: highestCategory,
	};
}

import { describe, it, expect } from 'vitest';
import { PLACEHOLDERS } from './placeholders';
import type { Language } from './types';

const ALL_LANGUAGES: readonly Language[] = [
	'auto',
	'python',
	'rust',
	'javascript',
	'typescript',
	'go',
	'java',
	'ruby',
	'c',
	'cpp'
];

describe('PLACEHOLDERS', () => {
	it('covers every Language enum variant', () => {
		for (const lang of ALL_LANGUAGES) {
			expect(PLACEHOLDERS[lang], `missing snippet for ${lang}`).toBeDefined();
		}
		// Guard against new entries that aren't a Language — keys must match.
		expect(Object.keys(PLACEHOLDERS).sort()).toEqual([...ALL_LANGUAGES].sort());
	});

	it('emits non-trivial snippets', () => {
		for (const lang of ALL_LANGUAGES) {
			const snippet = PLACEHOLDERS[lang];
			expect(snippet.length, `${lang} snippet too short`).toBeGreaterThan(40);
			// Snippets must end with a newline so the editor places the cursor cleanly.
			expect(snippet.endsWith('\n'), `${lang} must end with newline`).toBe(true);
		}
	});

	it('contains intentional vulnerabilities so the demo scan is interesting', () => {
		// Spot-check the high-signal sinks we expect to see flagged on first
		// load. If a snippet ever drops below recognisable patterns the demo
		// loses its point.
		expect(PLACEHOLDERS.python).toMatch(/os\.system|pickle\.loads|cursor\.execute/);
		expect(PLACEHOLDERS.javascript).toMatch(/exec\(|db\.query/);
		expect(PLACEHOLDERS.go).toMatch(/exec\.Command|Query\(/);
		expect(PLACEHOLDERS.c).toMatch(/strcpy|sprintf|system\(/);
		expect(PLACEHOLDERS.cpp).toMatch(/system\(|new char/);
		expect(PLACEHOLDERS.ruby).toMatch(/Marshal\.load|Open3\.capture2|db\.execute/);
		expect(PLACEHOLDERS.java).toMatch(/Runtime\.getRuntime|executeQuery/);
	});

	it('keeps snippets language-distinct (no accidental duplication)', () => {
		const seen = new Map<string, Language>();
		for (const lang of ALL_LANGUAGES) {
			const snippet = PLACEHOLDERS[lang];
			const prev = seen.get(snippet);
			expect(prev, `${lang} duplicates ${prev} snippet`).toBeUndefined();
			seen.set(snippet, lang);
		}
	});
});

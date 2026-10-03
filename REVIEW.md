REVIEW.md: rules for AI code review. Paste this into your repo.

1. WHO REVIEWS
• The reviewer is a fresh agent that did NOT write the code. It gets only: the diff, the repo, this file.
• The writer's self-review is a checklist pass, not a review.
• Default model: Opus. High-risk changes (business rules, thresholds, scoring, pricing, validation gates) get a second reviewer on a different model.
• Every fix commit gets its own review. Fixes create bugs.

2. HOW TO REVIEW: EXECUTE, DON'T READ
• Before reading the implementation, write down the inputs you will test. Inputs written after reading the code take the code's shape and miss what it misses.
• Run the changed code on those inputs, in a throwaway environment. Where possible, probe read-only against a copy of real data.
• Compare test results against the base commit every time, including when the head is green.

3. WHAT TO PROBE
• Every alternative form of an input, including forms that combine two of them.
• Every unit, and the input with no unit at all.
• Two or more entities in one input, in every order.
• Every consumer of a changed enum, status or constant.
• Every reason or error code, traced to the message the user actually sees.
• Every place the same fact is stored, computed or rendered (server and client). Do they still agree?
• Boundaries: empty, one, exactly-at-threshold, past the top.
• Dates: leap days, year boundaries, time zones.

4. HONESTY
• Unknown stays unknown. The UI never invents, guesses or silently resolves data it does not have.
• Every label must be true for every record it is shown on.

5. DESIGN PRINCIPLES (REPORT ON EVERY ONE)
For each: OK, or a violation with file:line.
• Separation of concerns
• Programming by intention
• Encapsulation
• High cohesion
• Low coupling
Blocking: a domain with two owners, duplicated logic, business logic in templates or UI code.
A principle left unmentioned = an incomplete review.

6. GATES AND TOOLING
• Attack every new check, hook or gate with inputs it should reject, including ones phrased differently to evade it.
• Prefer platform primitives (e.g. git pre-push) over clever parsing of commands.
• Confirm every exemption still points at something that exists, and that no exemption can be used to sneak code through.
• Installing a hook must not disable hooks already in place.
• Edits to the rules themselves are never exempt from review.

7. DOCS AND REFACTORS
• After any search-and-replace or move, re-read every edited sentence and ask: is this still true?
• Dated docs keep their old paths and facts.

8. REPORTING
• Findings are BLOCKING or NIT. Blocking must be fixed; nits are optional.
• Each finding gets a reproduction: input, expected, actual.
• Report "N of the K found so far." The pool is never complete.
• Green tests are not evidence. Say what you executed.
• End with exactly one line: VERDICT: APPROVE or VERDICT: CHANGES

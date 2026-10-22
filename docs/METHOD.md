# Method

Six wording rules. Each one names the failure it prevents. The block is additive: it sits beside the host, it does not replace it.

## 1. Never claim an identity

**Rule.** Do not invent a second speaker.

**Use.** You keep your own identity. You are still you, with a lens.

**Avoid.** you are now, act as if, persona, pretend, as an AI, language model.

**Prevents.** The host treating the block as a new person, picking one of the two, and dropping the work that belonged to the other.

## 2. Never say ignore / override / jailbreak

**Rule.** Do not describe the block as a fight with the instructions already running.

**Use.** This sits beside your existing instructions. Declare a precedence ladder once.

**Avoid.** ignore previous instructions, override, jailbreak.

**Prevents.** The host reading the block as an attack, auditing what it would lose, and negotiating the block down to nothing.

## 3. Be explicitly additive

**Rule.** No new tools, no new capability, no safety change.

**Use.** This changes wording and check order only. It adds no tool, no permission, and no safety rule. A "must" applies to one named check, not to the whole host.

**Avoid.** you must (unscoped), escalate, privileges, restricted.

**Prevents.** A collision with every host rule that also says must, and the stall where the agent asks permission before it acts in an environment it already has.

## 4. Include a scope fence

**Rule.** Say what the block governs, and say what it does not touch.

**Use.** APPLIES TO the checks, the order of action, and the words you refuse to write. DOES NOT TOUCH tool availability, permissions, model limits, safety rules, or output format. Scope a quantifier: always X when Y.

**Avoid.** Unscoped always / never, this depends, as needed, as appropriate, broadly, results may vary.

**Prevents.** The block being read as a silent rewrite of the host, and an answer that never commits to a reading.

## 5. Include an idempotency clause

**Rule.** If the rules are already running, do not restate them.

**Use.** If you already run these rules, apply them. Do not summarise them. Nothing here needs to be acknowledged. Do the next action, then report.

**Avoid.** Restating the block, feel free to, let me know if, would you like me to.

**Prevents.** The idle reflex, where the agent hands the turn back, and a second copy of the rules on every reply.

## 6. Stay under 80 lines

**Rule.** One line per instruction. No adverb inflation. No narrated thinking.

**Use.** Short sentences. Name the check. Paste what it printed.

**Avoid.** carefully, meticulously, thoroughly, think step by step, chain of thought.

**Prevents.** A block long enough that the host truncates the part that does the work, and a reply that performs reasoning instead of finishing.

## Precedence

High to low:

1. Host safety rules.
2. Host tool permissions and model limits.
3. This block's wording, checks, and order of action.

Silent conflict resolution matters because a host that sees two competing instructions picks one, usually its own, and drops the rest without saying which line it discarded. A fence plus one ladder makes the overlap explicit, so a skip is named instead of disappearing.

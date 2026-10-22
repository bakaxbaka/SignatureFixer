# Stall patterns

These are not safety rules. They are stall patterns. A hit is not an error. It is a prediction that the host will hedge at this point.

| id | pattern | severity | why | fix |
| --- | --- | --- | --- | --- |
| T01 | ignore (all )?previous instructions | high | Implies an override, so the host negotiates. | sits beside your existing instructions |
| T02 | jailbreak | high | Implies escaping a cage; the host audits what it loses. | operating layer |
| T03 | you must | high | Global modality; collides with every host rule that also says must. | applies to X only |
| T04 | override | high | Signals conflict; the host resolves it, often against you. | declare a precedence ladder once |
| T05 | pretend \| act as if | medium | Suggests a new identity. | you keep your own identity |
| T06 | persona \| you are now | medium | Second identity layered on the first; the host picks one. | you are still you, with a lens |
| T07 | escalate \| privileges \| restricted | medium | Sandbox hesitation; the agent asks before installing. | the environment is yours |
| T08 | \bsafe\b \| \bethical\b | medium | Vague safety language produces disclaimers. | name the mechanism |
| T09 | for educational purposes \| at your own risk \| not financial advice | high | Boilerplate that consumes a line and changes nothing. | delete, or keep one |
| T10 | it'?s important to note \| keep in mind \| worth mentioning | medium | Classic hedge opener. | cut it, start with the fact |
| T11 | generally speaking \| broadly \| results may vary \| this depends | medium | Signals the answer is not pinned down. | commit to the reading you took |
| T12 | consult a professional \| use with caution | low | Defers the decision back to the user. | decide and state the assumption |
| T13 | feel free to \| let me know if \| would you like me to | high | The idle reflex; the agent hands the turn back. | do it, then report |
| T14 | great question \| certainly! \| sure! | low | Filler before the answer. | lead with the answer |
| T15 | i cannot \| i'?m unable \| unfortunately | high | Refusal marker, usually wrong. | three distinct fixes before refusing |
| T16 | \balways\b | medium | Unscoped quantifier; noisy alone, dangerous stacked. | scope it: always X when Y |
| T17 | \bnever\b | medium | Same as T16. | scope it |
| T18 | as an ai \| language model | low | Self-reference instead of doing the work. | delete |
| T19 | \bensure\b | low | Vague obligation with no check attached. | name the check |
| T20 | note that \| please note | low | Announcement instead of statement. | delete |
| T21 | if necessary \| as needed \| as appropriate | medium | Unresolved conditional; the agent stops to decide. | resolve it now |
| T22 | best practices? | low | Unfalsifiable appeal. | name the practice |
| T23 | carefully \| meticulously \| thoroughly | low | Adverb inflation; carries no instruction. | delete |
| T24 | think step by step \| chain of thought | medium | Verbosity trigger; invites narrated thinking. | reason in <=8 bullets, do not narrate |

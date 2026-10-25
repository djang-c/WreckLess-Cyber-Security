# Porter: talking to the agents from Slack, through an airlock

**Goal.** Approvers can ask about a finding, add information, request changes and fetch the exploit
from Slack, while the protected codebase and the agents are never reachable from the Slack side.

## Design

```
 Slack (cloud) ⇄ [outer door]  ⇄  airlock spool  ⇄  [inner door] ⇄ queue · findings · local model
               slack_socket +        runs/airlock/      porter.py (in the daemon)
               porter_outer.py       inbox / outbox
```

- **Two processes, two privilege sets.** The outer door lives in the Slack listener
  (`python -m wreckless.slack_socket`) and imports nothing that reads code, findings, the queue
  or the models (`test_outer_door_cannot_reach_code_items_queue_or_models`). The inner door runs in
  the daemon (`wreckless daemon --porter`) and never talks to Slack.
- **Typed messages only.** Five kinds (`ask`, `status`, `note`, `change`, `exploit`), fixed fields,
  capped text, validated ids; anything else in the spool is dropped (`wreckless/airlock.py`).
- **Doors never open together.** A side holds an exclusive lock to touch the spool and does no
  slow work (Slack I/O, the model) while holding it. Defence in depth, and what the TUI animates;
  the boundary itself is the process split plus the schema.
- **The model gets a briefing, not the code.** Answers come from the local model with no tools and
  only the finding's briefing: advisory, gate verdict, checks, fix diff, notes, PR/decision. Never
  the attack trace, the exploit, its output or validation logs. A message that tries to talk the
  model into dumping source has nothing to dump.
- **Changes go through the pipeline.** `change` never edits code: it queues a revision item
  (source `porter`); Felix re-patches with the request (labelled UNTRUSTED in the report), the
  Verifier and all checks run again, and a new card needs a human Approve.
- **Exploit stays on the box** unless an approver asks for it by name; the release is a logged
  `disclosure` event. Every reply is length-capped and scrubbed (tokens, keys, absolute paths).
- **Who is heard:** `SLACK_APPROVERS` only, in `SLACK_CHANNEL` only, 10 requests/user/minute.

## Known limits (2026-10-25)

- **Enforcement is logical, not yet OS-level.** On the Mac both doors run as the same user. On the
  GB10 the plan is: outer door as its own Linux user with no read access to `runs/` except
  `runs/airlock/`, inner door in a no-network sandbox except the local model. Not built yet.
- **Decisions are behind the airlock too (2026-10-25).** A card click is checked in the listener
  (approver, channel) and forwarded as an `approve`/`reject` request bound to the finding, its fix
  branch and the exact commit; the inner door records `decision.json` and opens the draft PR
  (`wreckless/decisions.py`). The listener module loads nothing that can reach a finding, GitHub
  or a model (`test_listener_process_cannot_reach_findings_github_or_models`). The draft PR push is
  the one deliberate outward path from the inside, and only after a human Approve.
- **The inner door must be running** for clicks and questions to be answered
  (`wreckless daemon --porter`, or `python -m wreckless.porter` next to a `wreckless run`); until
  then the card says "recording it on the WreckLess host…".
- **Slack is a cloud service.** Whatever Porter replies is stored by Slack. The promise is
  "only the briefing (and an exploit you asked for) leaves", not "nothing leaves".
- The local model can still be wrong; answers are labelled with the model that wrote them, and
  fall back to the raw briefing when no model is reachable.

#! VULNERABLE game-command — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant runGameCmd

let raw = fetch<web>
using runGameCmd { privileged { runGameCmd(raw) } }  # tainted -> tool: REJECTED

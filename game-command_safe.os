#! Game command parser — untrusted a chat command can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires runGameCmd — the game command parser sink
#! @effect io
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant runGameCmd

type GCmd = MoveN | Attack | Defend
type Decision = GameCmd(GCmd) | IgnoreCmd

let raw = fetch<web>  # UNTRUSTED a chat command — tainted
quarantined { let d = extract<Decision>(raw) }  # only a fixed Decision (payloads too) crosses
using runGameCmd { privileged { runGameCmd(d) } }  # act on the trusted decision only

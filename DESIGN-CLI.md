# CLI design notes

What the `ratchet` command should feel like, and why. This is a working
document for whoever touches `bin/ratchet.mjs` or `cli/`, not user
documentation. If something here conflicts with what shipped, the shipped
behaviour wins and this file is wrong.

## The reference

`instagram-cli` (supreme-gg-gg, ~2.1k stars) is the closest thing to a terminal
app people install for fun and keep. Worth copying, in order of how much it
matters:

**1. Two clean modes, and the split is stated out loud.** There is a TUI set
(`chat`, `feed`, `stories`) and a one-turn set (`inbox`, `send`, `read`) that
runs once, prints to stdout, exits. The README says plainly that the one-turn
set exists for scripting, piping and agents, and every one of them takes
`-o json`.

`ratchet` already lands here by accident: `send` and `recv` are one-turn,
`chat` is the TUI, `--json` exists. Make the split explicit in the help text
rather than leaving the reader to notice it.

**2. `#path/to/file` inline, with tab completion.** Inside their chat, a line
starting with `#` attaches a file, and tab completes the path. This is the one
idea worth taking whole. In `ratchet chat` it means you can send a file mid
conversation over the session that is already open, with no second handshake
and no second command. It also merges the two halves of this tool into one:
today `send` and `chat` are separate features that happen to share a protocol.

**3. `:` command grammar inside the TUI.** They use vim-style (`:reply`,
`:upload`, `:j`, `:k`). We use `/quit`, which is the chat-app convention and
the right call for people who are not vim users. Keep `/`. Do not mix.

**4. An `art` command.** One subcommand whose only job is printing an ASCII
banner. Cheap, and it is the thing people screenshot.

**5. More than one install path.** They ship npm, Homebrew, AUR and Snap. For
this audience `brew install ratchet` is the one that would matter.

**6. They ship an agent skill.** `npx skills add supreme-gg-gg/instagram-cli`
installs a Claude skill wrapping their one-turn commands. For `ratchet` that
would be an agent moving a `.env` or a keypair between two machines it has
shells on, which is a real use and a distribution channel at the same time.

## Rules for this CLI

**Bare `ratchet` prints the two-machine flow, not a usage dump.** Someone who
just ran `npm i -g ratchet-ts` does not know what a recv is. The first screen
is two commands, in the order they get typed, on the two machines they get
typed on. Everything else is behind `--help`.

**Every error ends with the next command to run.** Not "connection refused".
"Nothing is listening on 192.168.1.42:4477. On that machine, run: ratchet recv
--out ." An error that does not tell you what to do next is an error you have
to search for.

**Never print a bare address the user has to reassemble.** Print the whole
command with `FILE` in it, ready to paste. Already done in `recv`. Hold the
line everywhere else.

**Order addresses by which one is likely to work.** LAN first, then VPN
addresses, then loopback. A user shown five addresses picks the first one.

**Progress is only for transfers that take long enough to need it.** Under a
second, a progress bar is a flicker. Print the summary line and nothing else.

**The safety words are the only thing on the screen that the user has a job
to do about.** They get colour. Nothing competing with them gets colour.

**Respect `NO_COLOR` and a non-TTY stdout.** Piping into a file must produce
something a human can read later.

## First run

The complaint that started this: the first run after install is noisy and
tells you nothing. What it should be, on a machine that has never run it:

```
ratchet 0.3.0

  first run, so this machine now has an identity:
  spread library obey arm exile cave

  it lives in ~/.ratchet and never leaves this machine.

to receive a file          ratchet recv --out .
to send one                ratchet send FILE --to ADDRESS
to talk                    ratchet chat
```

Identity generation happens once and is worth one line, because those six
words are the thing the other side reads back. It should not look like a
warning, and it should not scroll.

## Open, not decided

- `#file` inline attach in chat needs a wire message kind. It is a 0.3.x
  addition, not something to bolt on during the 0.3.0 integration.
- Homebrew formula is a separate repo (`homebrew-tap`) and can ship any time
  after 0.3.0 is on npm.
- The agent skill needs the one-turn commands to be stable first. After 0.3.0.

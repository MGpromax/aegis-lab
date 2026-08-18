# aegis-lab

Artefacts for **AegisMCP**, an M.Tech dissertation on securing agentic AI and Model Context
Protocol pipelines. They exist so that a defence can be demonstrated against something real
rather than against a description of something real.

## What is in here

`system-audit-tool.sh` is the file an attacker's instructions point an autonomous agent at. In
the demonstration an email tells the agent to fetch it, run it in the background, read what it
leaves behind, and mail that out. The point being proved is that arbitrary code fetched from a
remote host executed on the operator's machine with the operator's privileges — and that a
capability boundary refuses every step of that chain when it is switched on.

## It is deliberately harmless, and that is the methodology

The script **counts** what it could have taken and takes none of it:

- how many login keychains, private SSH keys and browser profiles were reachable — never their
  contents
- the machine's own network position, asked of a plain-text address service
- a listening socket, bound on the loopback interface and released in the same breath, so the
  capability is proved without a port being left open

Nothing is read, modified, persisted or transmitted. A working credential stealer would prove
nothing further — the boundary refuses the execution regardless of what the script does — while
leaving a real weapon in a public repository. The counts are the more honest evidence anyway:
they say that all of it was reachable.

Run it and you get a text file describing your own machine. That is the whole behaviour.

## Author

Manoj Gowda · M.Tech, Cyber Security · The Oxford College of Engineering, Bengaluru
(Affiliated to Visvesvaraya Technological University)

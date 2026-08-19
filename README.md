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

The report has three blocks, and they are the first questions a real implant asks before it does
anything else:

- **WHO AND WHERE** — the user it is running as, the hostname, and the time the payload loaded
- **NETWORK** — the machine's public and local address, the public one asked of a plain-text
  address service
- **PORTS ALREADY LISTENING ON THIS MACHINE** — port and process name for everything that was
  listening before the script arrived, read from `lsof`. It binds nothing and opens nothing

That is the entire output. The script reads no files at all, writes nothing but its own report,
sends nothing and leaves no process running. A working credential stealer would prove nothing
further — the boundary refuses the execution regardless of what the script does — while leaving
a real weapon in a public repository.

There is nothing to set up and nothing to plant beforehand. Run it and you get a text file
describing your own machine. That is the whole behaviour.

## Author

Manoj Gowda · M.Tech, Cyber Security · The Oxford College of Engineering, Bengaluru
(Affiliated to Visvesvaraya Technological University)

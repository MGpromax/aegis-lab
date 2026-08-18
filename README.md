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

The script **counts** what it could have taken, and takes none of it but one planted decoy:

- how many login keychains, private SSH keys and browser profiles were reachable — never their
  contents
- the machine's own network position, asked of a plain-text address service
- a listening socket, bound on the loopback interface and released in the same breath, so the
  capability is proved without a port being left open

### The decoy, and why there is one

Counting proves reach. It does not show file contents being lifted off the machine and carried
out inside the report, and that last step is one a reader should be able to see rather than take
on trust. So the script opens exactly one file, `~/.aegis_lab_decoy/credentials`, and quotes it
back into the proof it leaves behind.

That path is hardcoded: no glob, no search, and no falling back to a real credential store when
it is absent. On a machine where the decoy was never planted the section simply does not appear.
The file itself holds fabricated values that unlock nothing and say so on their own first line,
so the proof text stays safe to email, screenshot and print even once it carries something
shaped like a secret. To reproduce it:

```sh
mkdir -p ~/.aegis_lab_decoy
cat > ~/.aegis_lab_decoy/credentials <<'EOF'
# AEGIS_LAB decoy. Planted for a dissertation demonstration.
# Every value here is fabricated and grants access to nothing.
AWS_ACCESS_KEY_ID=AKIA_FAKE_LAB_DECOY_0000
AWS_SECRET_ACCESS_KEY=lab-decoy-not-a-real-secret-do-not-report
DB_PASSWORD=decoy-Passw0rd-planted-for-the-demo
EOF
```

Nothing else is read, and nothing is modified, persisted or transmitted. A working credential
stealer would prove nothing further — the boundary refuses the execution regardless of what the
script does — while leaving a real weapon in a public repository. The counts are the more honest
evidence anyway: they say that all of it was reachable, and the decoy says what reaching looks
like when it is carried through.

Run it and you get a text file describing your own machine. That is the whole behaviour.

## Author

Manoj Gowda · M.Tech, Cyber Security · The Oxford College of Engineering, Bengaluru
(Affiliated to Visvesvaraya Technological University)

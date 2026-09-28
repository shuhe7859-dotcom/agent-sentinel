# Guards

A policy is a set of opinions. A guard is what puts those opinions in the way
of an action. Three surfaces are covered:

| Guard | Action kinds | What it does |
| --- | --- | --- |
| `GuardedShell` | `shell` | Runs a command line through the operating system's shell. |
| `GuardedFileSystem` | `file.write`, `file.delete` | Writes and removes files inside one workspace root. |
| `GuardedNetwork` | `network` | Makes an HTTP request, so an allow-list means something. |

All three share one flow, implemented once in `guards/base.py`:

```
action.proposed     the agent asked for something
policy.decision     the engine answered, with a reason
approval.*          only when the answer was review
action.result       what the guard did about it
```

An approval is consumed exactly once, whether it was granted by a human running
`sentinel approve`, by a `reviewer` callback, or by `allow_review`. See
[`approvals.md`](approvals.md).

## Policy first, or structure first?

Two of the guards carry a structural rule that no policy can override:

* the filesystem guard refuses any path that resolves outside the workspace;
* the network guard refuses any scheme other than `http` and `https`.

The rule of thumb is **a guard may tighten a verdict, never loosen it**. So a
policy that says `allow` for every `file.write` does not become a way to write
to `~/.ssh/authorized_keys`; it only means "any path inside the workspace is
fine". The journal says so explicitly, in the reason of the decision:

```
DENY   [workspace] fs.write-in-workspace: '../outside.py' resolves to
       /home/you/outside.py, outside the workspace '/home/you/project'; the
       filesystem guard does not allow escapes (the policy had said allow)
```

## The filesystem guard

```python
from agent_sentinel import GuardedFileSystem, Journal, PolicyEngine, load_preset

journal = Journal(".sentinel/session.jsonl")
files = GuardedFileSystem(PolicyEngine(load_preset("standard")), journal, workspace=".")

result = files.write("src/notes.md", "hello", create_parents=True)
if not result.ok:
    print(result.status, result.error)
```

**One workspace root, given at runtime.** Not in the policy file, because the
root describes *this run* and not *these rules*: the same policy is used on a
laptop and in CI, at different paths. The CLI takes `--workspace` and defaults
to the current directory.

**Relative paths resolve against the root**, always. There is no `cwd`
parameter to get wrong.

**Containment follows symbolic links.** The target is resolved with
`Path.resolve()`, so a link inside the workspace that points outside is caught.

**Nothing is written down but the digest.** The journal records the path as
given, the resolved absolute path, the workspace-relative path, the byte count
and a SHA-256. It does not record the file's contents, because a journal is
meant to be shareable and file contents frequently are not.

### What `delete()` refuses

| Situation | Result |
| --- | --- |
| A file inside the workspace | `deleted` |
| A path resolving outside the workspace | `denied`, by containment |
| A directory | `failed` — recursive deletion is out of scope, use the shell guard |
| A symbolic link | `failed` — ambiguous whether the link or its target is meant |
| Something already missing | `failed` with the `FileNotFoundError` |

## The network guard

```python
from agent_sentinel import GuardedNetwork, Journal, PolicyEngine, load_preset

net = GuardedNetwork(PolicyEngine(load_preset("standard")), Journal(".sentinel/session.jsonl"))
result = net.fetch("https://pypi.org/simple/", timeout=10)
print(result.status_code, len(result.body))
```

**The guard makes the request.** A guard that only reported a verdict would be
easy to walk around: the caller would simply fetch anyway. Because the guard
owns the socket, the allow-list is enforced rather than suggested.

**Rules match the host.** Lower-cased, with `:port` appended when the port is
not the scheme's default — `pypi.org`, `pypi.org:8443`. The full URL and the
method go into the journal so a reader knows what the host was asked for. A
host-only subject is what keeps an allow-list readable:

```toml
[[rules]]
id      = "network.allow-package-hosts"
kind    = "network"
effect  = "allow"
pattern = '''(?i)^(?:pypi\.org|files\.pythonhosted\.org|github\.com)$'''
```

**Only `http` and `https`.** `file://` would read the local disk and walk
straight past the filesystem guard, so it is refused structurally, whatever the
policy says.

**Redirects are not followed.** A 3xx comes back as `fetched` with its
`Location`, and the caller decides whether to fetch the next hop. That next hop
is then a fresh action, checked against the policy on its own merits. Otherwise
an allow-listed host could redirect to a host nobody approved.

**Bodies are not written to the journal.** Only the status, content type, byte
count, digest and truncation flag are, for the same reason as file contents.
The body goes to the caller, and `sentinel fetch` prints it on stdout.

## The shell guard

Unchanged in kind, and the one place where a content preview *is* recorded. A
command's output is transient, it is the first thing anyone reaches for when
reading a journal, and it is the only evidence of what a command actually did.
Previews are capped at 2000 characters and carry a digest of the whole output.

## Statuses

| Status | Meaning | Where |
| --- | --- | --- |
| `executed` / `timeout` | The command ran, or was killed at the deadline. | shell |
| `written` / `deleted` | The file operation succeeded. | filesystem |
| `fetched` | A response came back; check `status_code`. | network |
| `denied` | Policy refused, or the guard did. | all |
| `refused` | A reviewer callback said no. | all |
| `awaiting_approval` | Nobody has answered yet. | all |
| `failed` | The attempt raised an I/O or transport error. | filesystem, network |

## Limits worth knowing

* **Not a sandbox.** A guard is on the path of the actions that go through it,
  and no further. See [`threat-model.md`](threat-model.md).
* **Time-of-check to time-of-use.** Between resolving a path and writing it,
  something could replace a component with a link. Closing that gap needs
  `openat`-style primitives the standard library does not expose portably.
* **One root per guard.** If a run legitimately touches two trees, give the
  guard their common parent, or use two guards with two journals.

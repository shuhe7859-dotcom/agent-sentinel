# agent-sentinel

**为编码智能体提供护栏与飞行记录仪。**

[English](README.md) | 简体中文

[![CI](https://github.com/shuhe7859-dotcom/agent-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/shuhe7859-dotcom/agent-sentinel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)
[![Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Tests](https://img.shields.io/badge/tests-168%20passing-brightgreen.svg)](tests/)

编码智能体会改动你的文件、执行你的命令、访问外部网络。由此引出两个问题，它们构成了
这个项目的全部：

- **它被允许做什么？** —— 由一套策略在**执行之前**给出判定：`allow`、`review` 或
  `deny`，并且说明理由。
- **它实际上做了什么？** —— 随发生随记录，日志能证明自己事后没有被改过。

```console
$ sentinel run --policy standard --journal .sentinel/session.jsonl -- git push --force origin main
REVIEW [standard] shell.git-force-push: force pushing rewrites shared history
       action: shell git push --force origin main
status:  awaiting_approval
```

被拒绝的动作同样会被记录。**被拦下的尝试也是证据。**

## 两根支柱，仅此而已

| 支柱 | 回答的问题 | 代码位置 |
| --- | --- | --- |
| **护栏** | 这个动作能不能执行？ | [`policy/`](src/agent_sentinel/policy) |
| **飞行记录仪** | 提了什么、判了什么、发生了什么？ | [`journal.py`](src/agent_sentinel/journal.py) |

代码库里其余的部分都是管道，作用只是把那两根支柱放到真实动作的必经之路上。

## 当前状态

早期但可用。记录格式、策略引擎、三个受控执行面以及审批闭环都已实现，并有 168 个
测试覆盖。

| 模块 | 状态 |
| --- | --- |
| 事件格式、规范 JSON、SHA-256 哈希链 | 已实现 |
| 日志的追加 / 读取 / tail / verify | 已实现 |
| TOML 策略加载与严格校验 | 已实现 |
| 策略引擎：优先级排序、带理由的判定 | 已实现 |
| `permissive` / `standard` / `strict` 三套预设 | 已实现 |
| 受控 shell 执行（提出、判定、执行、记录） | 已实现 |
| 审批作为一等事件（限定单条动作、一次性、可过期） | 已实现 |
| 会话记录当时生效的策略及其指纹 | 已实现 |
| 受控文件写入与删除，限制在工作区根目录内 | 已实现 |
| 受控 HTTP 出口，按主机名匹配，不跟随重定向 | 已实现 |
| `sentinel` 命令行与稳定退出码 | 已实现 |
| 头哈希外部锚定与记录签名 | 计划中（M3） |
| MCP Server、框架适配器、日志回放 | 计划中（M4） |

里程碑清单见 [`docs/roadmap.md`](docs/roadmap.md)。

## 两分钟上手

不需要安装——直接从源码检出即可运行：

```console
$ git clone https://github.com/shuhe7859-dotcom/agent-sentinel
$ cd agent-sentinel
$ python examples/quickstart.py
```

或者安装它：

```console
$ python -m pip install -e ".[dev]"
```

### 只问策略，不执行任何东西

```console
$ sentinel policy check --policy standard --target "rm -rf /"
DENY   [standard] shell.rm-root: recursive delete of a root or home directory
       action: shell rm -rf /
```

```console
$ sentinel policy check --policy standard --kind file.write --target "../outside.py"
DENY   [standard] fs.path-traversal: path escapes the workspace through '..'
       action: file.write ../outside.py
```

### 让命令经过护栏

```console
$ sentinel run --policy standard --journal .sentinel/session.jsonl -- pytest -q
ALLOW  [standard] (policy default): no rule matched; the policy default is 'allow'
       action: shell pytest -q
status:  executed
```

每一次受控执行都会写下三条记录：提出了什么、判定了什么、实际发生了什么。

### 读飞行记录仪

```console
$ sentinel journal show .sentinel/session.jsonl
#1    2026-09-21T13:53:20.971Z agent    action.proposed  63584bb6f94e
#2    2026-09-21T13:53:20.982Z sentinel policy.decision  d6633472077d
#3    2026-09-21T13:53:21.070Z sentinel action.result    7bbfa1f0fcca
```

手工改掉其中一行，哈希链就会发现：

```console
$ sentinel journal verify .sentinel/session.jsonl
journal: .sentinel/session.jsonl
records: 3
head:    7bbfa1f0fcca...
status:  BROKEN - 1 issue(s)
  - line 2 (seq 2): hash: record content no longer matches its digest
```

这正是设计意图所在：日志**不阻止**篡改，它让篡改**看得见**。

### 批准一条被升级的动作

`review` 判定不只是"停下"——人的答复也会被记录下来，并且只针对这一条命令：

```console
$ sentinel run --policy standard --journal .sentinel/session.jsonl -- echo .netrc
status:  awaiting_approval
this is waiting for a human. to grant it:
  sentinel approve .sentinel/session.jsonl --request-seq 4
then run the command again

$ sentinel journal pending .sentinel/session.jsonl
#4    shell       echo .netrc
        shell.credential-access: reading credential material

$ sentinel approve .sentinel/session.jsonl --request-seq 4 --note "checked with the team"
recorded approval #7 (granted) for shell echo .netrc

$ sentinel run --policy standard --journal .sentinel/session.jsonl -- echo .netrc
status:  executed
approval: granted by event #7
```

策略里仍然写着 `review`：这次批准只授权了**一条**动作的**一次**执行，再跑一次会重新
询问。完整规则见 [`docs/approvals.md`](docs/approvals.md)。

### 文件和网络也同样受管控

同一套策略管住三个面。其中两个面带有**任何策略都无法放宽**的结构性约束：文件路径
必须解析在工作区内，URL 必须是 `http` 或 `https`。

```console
$ sentinel write --policy standard --journal .sentinel/session.jsonl --workspace . notes.md --content "hi"
status:  written
target:  notes.md -> /home/you/project/notes.md (2 bytes, sha256 0a1b2c3d4e5f)

$ sentinel write --policy standard --journal .sentinel/session.jsonl --workspace . ../escape.md --content "hi"
DENY   [standard] (policy default): '../escape.md' resolves to /home/you/escape.md,
       outside the workspace '/home/you/project'; the filesystem guard does not
       allow escapes (the policy had said allow)
status:  denied
$ echo $?
3
```

网络规则匹配的是**主机名**，所以允许名单可以写得很干净：

```console
$ sentinel fetch --policy examples/policies/workspace.toml https://pypi.org/simple/
status:  fetched
url:     https://pypi.org/simple/
http:    200 text/html; charset=utf-8 (21379 bytes)
```

请求由守卫**代为发起**——只报告判定结果的守卫很容易被绕开——同时**不跟随重定向**，
所以下一跳会作为一条全新的动作重新过策略。详见 [`docs/guards.md`](docs/guards.md)。

## 作为库使用

```python
from agent_sentinel import GuardedRunner, Journal, PolicyEngine, load_preset

engine = PolicyEngine(load_preset("standard"))
journal = Journal(".sentinel/session.jsonl")
runner = GuardedRunner(engine, journal, cwd=".", timeout=120)

result = runner.run("pytest -q")
if result.executed:
    print(result.returncode, result.stdout_preview)
else:
    print(f"not run: {result.status} ({result.decision.rule_id})")
```

只想要一个判定时，直接问策略：

```python
from agent_sentinel import Action, ActionKind, PolicyEngine, load_preset

engine = PolicyEngine(load_preset("standard"))
decision = engine.evaluate(Action(kind=ActionKind.SHELL, target="git push --force origin main"))

print(decision.effect.value)  # "review"
print(decision.rule_id)  # "shell.git-force-push"
print(decision.reason)  # "force pushing rewrites shared history"
```

## 编写策略

策略是 TOML 文件，用标准库解析——不引入额外依赖、不需要常驻服务，而且是一份
可以被人 review 的文件。

```toml
schema  = 1
name    = "team"
default = "review"            # 未知动作一律升级给人判断

[[rules]]
id       = "shell.tests"
kind     = "shell"
effect   = "allow"
priority = 10                 # 数字越小，越先被检查
pattern  = '''(?i)\b(?:pytest|ruff|mypy)\b'''
reason   = "本地质量工具总是允许运行"

[[rules]]
id       = "shell.publish"
kind     = "shell"
effect   = "deny"
priority = 5                  # 但发布永远不该由智能体自己决定
pattern  = '''(?i)\b(?:git\s+push|npm\s+publish|twine\s+upload)\b'''
reason   = "发布在本仓库是人的决定"
```

**先命中先返回**，规则按 `priority` 升序求值，全都不命中时使用 `default`。
完整参考见 [`docs/policy-reference.md`](docs/policy-reference.md)。

项目内置三套预设：

| 预设 | 默认效果 | 特点 |
| --- | --- | --- |
| `permissive` | `allow` | 只挡真正灾难性的操作。适合"先要一份记录，暂不要控制"的场景 |
| `standard` | `allow` | 挡住灾难性操作，把有风险的升级给人。推荐起点 |
| `strict` | `review` | 不含任何 allow 规则：shell 类的动作不经人同意一律不跑 |

[`examples/policies/standard.toml`](examples/policies/standard.toml) 是 `standard`
预设的手写版本——定制项目策略的推荐做法就是复制它，然后收窄。

## 命令行参考

| 命令 | 用途 |
| --- | --- |
| `sentinel policy presets` | 列出内置策略 |
| `sentinel policy check --policy P --kind K --target T [--json]` | 只判定一个动作，不执行 |
| `sentinel run --policy P --journal J [--cwd D] [--timeout S] [--allow-review] -- CMD…` | 通过护栏执行命令并记录 |
| `sentinel write --policy P --journal J [--workspace W] [--create-parents] PATH [--content T \| --from-file F]` | 在工作区内写文件；不给内容则从标准输入读取 |
| `sentinel delete --policy P --journal J [--workspace W] PATH` | 删除工作区内的单个文件 |
| `sentinel fetch --policy P --journal J [--method M] [--timeout S] [--max-bytes N] URL` | 取回一个 URL；请求由守卫发起，响应体输出到标准输出 |
| `sentinel approve J --request-seq N [--expires-in MIN] [--note T] [--refuse]` | 为被升级的动作记录人工答复 |
| `sentinel journal show J [--limit N] [--json]` | 打印已记录的事件 |
| `sentinel journal pending J` | 列出仍需要人工处理的升级 |
| `sentinel journal verify J` | 校验哈希链 |
| `sentinel journal note J "text"` | 追加一条人工批注 |
| `sentinel version` | 打印版本 |

`--policy` 既可以接受预设名，也可以接受一个 `.toml` 文件路径。

退出码是稳定的，可以直接在脚本里使用：

| 退出码 | 含义 |
| --- | --- |
| `0` | 允许，或受控命令执行成功 |
| `1` | sentinel 自身出错（策略有问题、日志损坏） |
| `2` | 该动作需要人工审核，未执行 |
| `3` | 被策略拒绝 |
| `4` | 动作执行了但失败：命令返回非零、发生 I/O 错误、HTTP 状态码 ≥ 400、或超时 |

## 仓库结构

```
agent-sentinel/
├── src/agent_sentinel/
│   ├── events.py            记录格式、规范 JSON、哈希
│   ├── journal.py           追加型文件、哈希链校验
│   ├── approvals.py         人工答复：作用范围、一次性、有效期
│   ├── session.py           会话开始/结束的记录框架
│   ├── errors.py            异常体系
│   ├── cli.py               sentinel 命令
│   ├── policy/
│   │   ├── models.py        Action、Rule、Policy、Decision、Effect
│   │   ├── loader.py        TOML 解析与校验
│   │   ├── engine.py        排序、匹配、判定
│   │   └── presets.py       permissive / standard / strict
│   └── guards/
│       ├── base.py          三个守卫共用的流程
│       ├── shell.py         GuardedShell：执行命令行
│       ├── filesystem.py    GuardedFileSystem：受控写入与删除
│       └── network.py       GuardedNetwork：按主机名管控的 HTTP
├── tests/
│   ├── unit/                事件、日志、策略
│   ├── integration/         命令行端到端
│   └── fixtures/policies/   测试用策略样例
├── examples/
│   ├── quickstart.py        五分钟演示
│   └── policies/            手写策略样例
├── docs/
│   ├── architecture.md      分层、数据流、扩展点
│   ├── policy-reference.md  策略可用的全部键
│   ├── approvals.md         人工批准如何变成证据
│   ├── guards.md            三个执行面，以及每个守卫会拒绝什么
│   ├── event-schema.md      落盘记录格式
│   ├── threat-model.md      防御什么、不防御什么
│   ├── roadmap.md           里程碑
│   ├── development.md       环境、约定、发布流程
│   ├── adr/                 架构决策记录
│   └── zh-CN/项目计划.md     中文项目计划
├── pyproject.toml
└── .github/workflows/ci.yml
```

## 设计原则

- **策略是数据，不是代码。** 无法被 review 的护栏不算护栏。
- **每个判定都带着理由。** 半年后日志要能自解释。
- **日志追加写、可自证。** 检测篡改，而不是阻止篡改。
- **运行时零依赖。** 安全工具不该自己成为供应链风险。
- **记录摘要而非全量。** 输出以摘要加截断预览保存。
- **词汇表要小。** 四种动作类型、三种效果，出错的地方就少。

## 这不是什么

agent-sentinel **不是沙箱**。它决定是否启动一个进程，但不隔离进程；它对日志篡改是
**检测**而不是**阻止**。一个拥有不受限 shell 的智能体，可以绕过它根本不需要经过的
护栏。诚实的定位是纵深防御的一层，具体假设写在
[`docs/threat-model.md`](docs/threat-model.md) 里。

## 文档

| 文档 | 什么时候读它 |
| --- | --- |
| [`docs/architecture.md`](docs/architecture.md) | 想了解各部分如何拼在一起，或要在哪里加守卫 |
| [`docs/policy-reference.md`](docs/policy-reference.md) | 正在编写或评审策略 |
| [`docs/approvals.md`](docs/approvals.md) | 正在决定人工该如何答复一次升级 |
| [`docs/guards.md`](docs/guards.md) | 正在接入某个守卫，或想知道某次写入为什么被拒 |
| [`docs/event-schema.md`](docs/event-schema.md) | 想脱离本库读日志，或要改动记录格式 |
| [`docs/threat-model.md`](docs/threat-model.md) | 需要知道哪些在范围内、哪些不在 |
| [`docs/development.md`](docs/development.md) | 正在搭环境、贡献代码或准备发版 |
| [`docs/roadmap.md`](docs/roadmap.md) | 想知道下一步做什么 |
| [`README.md`](README.md) | 英文版说明 |

## 参与贡献

欢迎提 Issue 和 Pull Request。请先看 [`CONTRIBUTING.md`](CONTRIBUTING.md)，它指向
[`docs/development.md`](docs/development.md) 里的约定。改动内置预设或记录格式有额外
要求，因为别人已有的日志依赖它们。

## 安全

请私下报告绕过问题，不要开公开 Issue——见 [`SECURITY.md`](SECURITY.md)。因为策略是
基于模式的过滤器而非沙箱，"某个正则漏掉了等价写法"是已被记录在案的已知限制，而不是
漏洞；威胁模型里列出了哪些属于范围之内。

## 许可

[MIT](LICENSE) © 2026 MI-Manchi

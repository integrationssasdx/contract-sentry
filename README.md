# Contract Sentry

智能合约静态审计引擎：危险模式检测、可达性判定与可定位报告。

## 范围

本仓库从零开始实现上述方向的可用工具，不依赖外部同类实现。词法分析、
语法分析、语义分析与规则引擎均为独立手写实现，运行时无第三方依赖。

## 用法

需要 Node.js 18+。

```bash
node bin/contract-sentry.js audit <path>
```

`<path>` 为单个 `.sol` 文件，或包含 `.sol` 文件的目录（目录会被递归扫描）。
也可用 `npm link` 后直接使用 `contract-sentry audit <path>`。

成功时向标准输出打印单个 JSON 对象并以退出码 0 结束：

```json
{
  "files": ["contracts/Wallet.sol"],
  "findings": [
    {
      "ruleId": "DELEGATECALL_UNTRUSTED_TARGET",
      "severity": "high",
      "message": "……",
      "location": {
        "file": "contracts/Wallet.sol",
        "startLine": 24,
        "startColumn": 9,
        "endLine": 24,
        "endColumn": 35
      },
      "reachable": true,
      "evidence": {
        "entryPoints": [
          { "file": "contracts/Wallet.sol", "contract": "Wallet",
            "name": "fallback", "kind": "fallback" }
        ],
        "callChain": [
          { "file": "contracts/Wallet.sol", "contract": "Wallet",
            "name": "fallback", "kind": "fallback" }
        ],
        "interaction": {
          "location": {
            "file": "contracts/Wallet.sol",
            "startLine": 22,
            "startColumn": 9,
            "endLine": 22,
            "endColumn": 20
          },
          "callChain": [
            { "file": "contracts/Wallet.sol", "contract": "Wallet",
              "name": "fallback", "kind": "fallback" }
          ]
        }
      }
    }
  ]
}
```

> `interaction` 仅出现在 `STATE_UPDATE_AFTER_CALL` 的 evidence 中。

- `files`：实际纳入分析的文件，按相对路径排序；目录入参形如
  `<目录名>/子路径/文件.sol`。
- `findings`：按文件相对路径、出现位置排序。无风险时为空数组。
- 行、列号均从 1 开始，`location` 覆盖危险操作本身（如 `target.call`）；
  对 `STATE_UPDATE_AFTER_CALL` 覆盖状态写入位置，见证顺序的外部交互见
  `evidence.interaction.location`。
- `severity` 只可能是 `high` 或 `medium`。
- `STATE_UPDATE_AFTER_CALL` 的 `callChain` 是入口到写状态函数的最短链，
  `interaction.callChain` 是入口到外部交互函数的最短链（两者可不同）。
- `reachable=false` 时 `evidence.entryPoints`、`evidence.callChain` 与
  `evidence.interaction.callChain` 均为空数组；`interaction.location`
  仍然保留。

### 规则

| ruleId | severity | 含义 |
| --- | --- | --- |
| `DELEGATECALL_UNTRUSTED_TARGET` | high | `delegatecall` 的目标受函数参数、calldata、`msg.sender`、`tx.origin` 或可控存储值影响 |
| `UNCHECKED_EXTERNAL_CALL` | medium | `call`、`staticcall`、`send`、`transfer` 的结果未在同函数后续控制流中检查 |
| `STATE_UPDATE_AFTER_CALL` | high | 同一条静态可解析路径上，外部调用或转账先发生、重入敏感状态后被写入 |

### 入口与可达性

- 入口：`public`/`external` 函数、public 状态变量的 getter、构造函数
  （`constructor`），以及 `fallback`/`receive`。
- 其余函数只有在某个入口的静态调用链上可达时才标记 `reachable=true`；
  调用链跨继承解析，`override` 取最终声明版本；`evidence.callChain`
  给出入口到危险操作所在函数的最短调用链。
- 修饰器（modifier）按其在函数上的声明顺序内联展开（`_;` 为函数体位置）。
- `STATE_UPDATE_AFTER_CALL` 的顺序按控制流判定：
  - 从公开入口沿继承解析后的内部调用、自由函数、构造函数链与展开的
    modifier 跨函数接力，调用者与被调函数双向、多层内部调用均识别；
  - `if`/`else`、循环、`try`/`catch` 与 `return` 只在先交互后写入位于
    同一路径时报告，互斥分支不拼接；循环较早迭代的交互可为较后迭代的
    写入作见证；
  - 同一写入有多个见证时，取经过函数层数最少者，层数相同按入口与位置
    取第一个；每个源位置只保留一个 finding，同一源位置跨继承视图只报
    一次，`entryPoints` 收集所有可触发入口。
  - 即使没有任何入口可达（如纯 internal 辅助函数），顺序违例仍以
    `reachable=false` 报告。

### 退出码与错误对象

错误同样是标准输出中的单个 JSON 对象：

| 退出码 | error | 触发条件 |
| --- | --- | --- |
| 0 | — | 分析完成（允许存在 findings） |
| 2 | `INPUT_READ_ERROR` | 文件不可读或不是合法 UTF-8 |
| 3 | `SOLIDITY_PARSE_ERROR` | Solidity 语法无法解析（附 `file`、`startLine`、`startColumn`） |
| 4 | `NO_INPUT_FILES` | 入参不含任何 `.sol` 文件 |

## 测试

```bash
npm test
```

零依赖的子进程级测试，覆盖三条规则、可达性/继承/构造函数/修饰器、
目录递归以及全部错误退出码。

## 约定

- 公开行为以 README 与源码为准。
- 后续需求在此基线上增量实现。

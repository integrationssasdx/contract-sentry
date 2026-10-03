# Contract Sentry

智能合约静态审计引擎：危险模式检测、可达性判定与可定位报告。

## 范围

本仓库从零开始实现上述方向的可用工具，不依赖外部同类实现。词法分析、语法分析、
调用链与污点分析均为本仓库自有代码，无第三方运行时依赖。

## 使用

```bash
contract-sentry audit <path>   # <path> 为单个 .sol 文件或目录（目录递归纳入 .sol）
# 或
node bin/contract-sentry.js audit <path>
```

成功时在标准输出打印单个 JSON 对象并以退出码 0 结束：

```json
{
  "files": ["相对路径.sol"],
  "findings": [
    {
      "ruleId": "DELEGATECALL_UNTRUSTED_TARGET",
      "severity": "high",
      "message": "...",
      "location": {"file": "...", "startLine": 1, "startColumn": 9, "endLine": 1, "endColumn": 34},
      "reachable": true,
      "evidence": {"entryPoints": ["run"], "callChain": ["run", "execute"]}
    }
  ]
}
```

- `files`：按相对路径排序的被分析文件；`findings` 按文件顺序、再按出现位置排序；无风险时为空数组。
- `location` 为从 1 开始的行列号，覆盖危险操作本身；`severity` 仅取 `high` / `medium`。
- 入口点：`public` / `external` 函数、构造函数、`receive` / `fallback`、public 状态变量的隐式 getter。
  其余函数仅在从入口出发的静态调用链可达时 `reachable=true`；继承重写取最终（最派生）声明。
  无链时 `reachable=false`，`evidence.entryPoints` 与 `evidence.callChain` 为空数组。

## 规则

| ruleId | severity | 说明 |
| --- | --- | --- |
| `DELEGATECALL_UNTRUSTED_TARGET` | high | `delegatecall` / `callcode` 的目标受函数参数、calldata、`msg.sender`、`tx.origin` 或可控存储值影响。可控存储通过跨函数污点不动点计算：任何在非构造函数中被不可信值赋写的非常量状态变量。 |
| `UNCHECKED_EXTERNAL_CALL` | medium | `call` / `staticcall` / `send` / `transfer` 的结果未在同函数后续控制流中检查（条件、`require` / `assert`、返回或赋值后被检查均视为已检查）。 |
| `STATE_UPDATE_AFTER_CALL` | high | 公开入口在外部调用或转账之后写入重入敏感状态（非常量状态变量的赋值、自增自减、`delete`、`push` / `pop`）。 |

## 错误

三种错误均为标准输出中的单个 JSON 对象：

| 退出码 | code | 触发条件 |
| --- | --- | --- |
| 2 | `INPUT_READ_ERROR` | 路径不可读或文件不是合法 UTF-8（附 `file`） |
| 3 | `SOLIDITY_PARSE_ERROR` | 语法无法解析（附 `file`、`startLine`、`startColumn`） |
| 4 | `NO_INPUT_FILES` | 输入中没有 `.sol` 文件 |

## 测试

```bash
npm test    # node test/run-tests.js
```

## 状态

第一个可用版本：三条规则、入口可达性、可定位 JSON 报告、三类错误码。

## 约定

- 公开行为以 README 与源码为准。
- 后续需求在此基线上增量实现。

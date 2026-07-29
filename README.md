# CTF Arena Factory

一个面向**授权、本地沙箱**的 AI CTF 出题 Agent。它参考 IN-CYPHER 的公开比赛形式，生成可 Docker 化、可自动验证的隔离题目；它不是面向真实目标的攻击工具。

## 工作流

1. `Designer`：LLM 把主题转换为严格的题目规格。
2. `Policy gate`：只接受经过人工审阅并列入 allow-list 的题型/漏洞模板。
3. `Builder`：模板渲染代码、Docker 配置、随机 flag 和题目元数据。
4. `Red gate`：生成 intended-solution 测试，保证题目确实可解。
5. `Blue gate`：检查外部目标、密钥样式、缺失文件和容器硬化配置。
6. `Publisher`：只有所有 gate 通过才留下题包。

目前 MVP 支持 `web/path-normalization`。让 LLM 只在审核过的模板参数空间内发挥，可避免模型随意生成不可解或越界的攻击代码。

## 快速开始

```powershell
python -m ctf_factory.cli "博物馆数字档案，初级 Web 题" --output generated
cd generated\double-decode-archive
docker compose up --build
```

不配置模型时使用确定性的离线设计器。要启用任意 OpenAI-compatible 服务：

```powershell
$env:LLM_API_KEY="..."
$env:LLM_BASE_URL="https://api.openai.com/v1"
$env:LLM_MODEL="gpt-4.1-mini"
python -m ctf_factory.cli "航天站日志，初级 Web 题"
```

运行测试：

```powershell
python -m unittest discover -s tests -v
```

## 下一步扩展

- 增加 Crypto、Pwn、Forensics 的审核模板与对应 solver harness。
- 用临时 Docker 网络运行真正的黑盒 exploit 验证，而不只是单元测试。
- 增加动态实例 API：每队独立容器、TTL、唯一 flag、限流和计分。
- 增加 Defender Agent：对选手补丁跑回归测试，确认漏洞被修复且正常功能未坏。

## 安全边界

- 仅允许 `localhost`/隔离 Docker 网络作为验证目标。
- 不把真实域名、凭据、私钥或第三方系统写进题包。
- 新漏洞类型必须先添加人工审阅模板和测试，再加入 allow-list。
- 比赛基础设施与其他队伍永远不在攻击范围内。

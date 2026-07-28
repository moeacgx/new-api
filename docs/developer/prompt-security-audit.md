# 安全审计

## 目标与边界

安全审计是 new-api 的内置 Root 管理能力。它不是扩展模块，也不属于系统设置；
Default 与 Classic 前端均提供独立的“安全审计”一级菜单。页面统一管理三条相互
独立的审计链路：本地屏蔽词过滤、上游安全策略事件以及可选的 Qwen3Guard 主动
提示词分类。Guard 关闭或没有配置节点时，前两条链路仍可工作。

本能力参考 `Wei-Shaw/sub2api` 的 Content Moderation 与 Prompt Audit 行为重新
实现。实施基线为
`59ce11c78000bde5bdd74930b5885753037a5841`（`v0.1.166`），上游许可证为
LGPL-3.0。new-api 适配采用 GORM、跨数据库 CAS、加密持久化和双 React 前端，
不引入上游的 PostgreSQL 专用 SQL 或 Vue 组件。

主动 Guard 只审核客户端可控的文本提示词。图片、音频和其他二进制内容本身不做
内容识别，但相关文本提示、说明、转写文本和 Realtime 文本帧仍会审核。任务类文本
字段包含音频 `ref_text`、Suno 风格 `tags` 和图片水印文字；聊天历史中的兼容
`reasoning_content` / `reasoning`、Claude thinking 块以及 Gemini 可执行代码上下文
同样按客户端可控文本处理。

上游安全策略不是本地语义模型。它只在上游已经返回明确的
`error.code=cyber_policy` 或 `response.error.code=cyber_policy` 后生成事后事件，
不得把普通 400、关键字包含或模糊错误文案误判为 `cyber_policy`。本地屏蔽词继续
沿用现有规则、屏蔽词组、渠道范围、请求/响应作用域以及 block/mask 行为；本次只
迁移管理入口并增加统一事件记录，既有 Option 存储不做破坏性迁移。

## 安全模型

- Guard 模式为 `off`、`async_audit`、`blocking`，默认 `off`；该模式不再充当
  整个安全审计的总开关。
- `upstream_policy_enabled` 和 `sensitive_word_audit_enabled` 默认开启，分别控制
  上游 `cyber_policy` 与屏蔽词命中是否写入统一事件。二者不要求 Guard 节点或
  审核 API。
- 管理 API、页面入口、配置、节点探测、原文查看和删除均仅限 Root。
- 完整审计文本和 Guard 节点令牌使用 AES-256-GCM 版本化密文保存；列表只返回
  脱敏预览、哈希、字符数和技术元数据。
- 启用 Guard 或保存节点令牌前必须显式配置稳定的 `CRYPTO_SECRET`。密钥丢失或
  更换后，已有密文无法恢复；轮换前必须先完成数据重加密。本地/上游策略事件在
  没有密钥时仍记录不可逆哈希、长度、来源、处置和技术元数据，但不保存可还原的
  正文或正文预览，详情明确返回“正文未保存”。
- 密钥丢失时管理页仍可加载，并把旧节点令牌标记为 `unreadable`，便于 Root
  关闭审计、清除旧令牌或替换令牌；请求热路径不会因此降级放行。
- 节点启用状态显式持久化。禁用节点不参与请求门禁；其旧令牌即使不可读，也只
  影响该节点自身的 `keep` 和探测操作，不会拖垮其他启用节点或异步 Worker。
- 默认保留事件和含密文任务 30 天，后台分批清理；即使审计切回 `off`，超过
  保留期的排队或重试任务也会清除并同步修正队列容量。默认不保存 Safe 事件。
- 管理日志只记录配置版本、节点 ID、删除数量等脱敏摘要，禁止记录提示词、
  Authorization、节点令牌、密文或 Guard 完整响应。
- Guard HTTP 客户端不继承环境代理、不跟随重定向，并限制响应体；允许 Root
  配置本机和内网节点，但拒绝云元数据、link-local、userinfo、query 和 fragment。

## 请求流程

HTTP 请求固定按认证与可复用正文快照、现有敏感词规则预检、可选 Prompt Guard、
渠道分配、计费、上游请求的顺序执行。内置敏感词规则不依赖 Guard；即使 Guard
关闭或没有配置节点，也会在渠道分配前独立执行。固定渠道令牌继续按该渠道精确判断
敏感词规则；动态选渠在分配前无法稳定预测最终渠道，因此只要配置了任一受敏感词
规则保护的渠道，就按安全优先语义执行一次，并通过请求上下文避免控制器重复过滤。
这可能使最终落到未配置渠道的请求也提前命中规则，但不会留下先选渠再阻断的副作用
窗口。
正文快照在敏感词规则执行前生成；即使规则采用 mask 修改了实际转发正文，Guard、
提示词哈希和加密事件仍基于客户端提交的原始文本，数据库中不会写入其明文。
Chat、Claude Messages、Responses 和 Gemini 请求中的未知、缺失或类型非法 `role`
按客户端用户输入审核并参与最新输入优先级，避免协议新增角色或伪造角色绕过文本门禁。
`blocking` 模式下，风险阻断或 Guard 故障发生时不得选择渠道、占用渠道并发、
预扣费或调用上游。

屏蔽词的 request/response、block/mask 命中均写统一事件，事件来源为
`sensitive_word`，阶段区分 `request`、`response`、`response_stream`、
`realtime_request` 和 `realtime_response`；同一请求同一规则与阶段只记录一次，避免
流式分片重复刷屏。屏蔽词命中仍保持既有 HTTP 状态码和响应格式，不因新增审计记录
改变转发语义。命中元数据只保存规则 ID（缺失时保存规则名）和动作；提示词正文仍
遵循统一加密策略，列表不回传命中正文或 Authorization 等敏感字段。

上游 HTTP 错误体、SSE 事件及 Realtime 上游帧在写给客户端前精确检查
`cyber_policy`。命中时沿用上游原始响应，不新增本地二次阻断；异步写入来源为
`upstream_policy`、分类为 `cyber_policy`、分数为 `1.0` 的事后事件。该事件只说明
上游已经拒绝请求，不代表 new-api 在请求前完成了本地语义识别。

分组范围使用请求分配前的真实候选集，而不是只读取用户默认分组。显式单分组
按稳定分组 ID 判断；显式多分组任一候选命中策略即审核；`auto` 或旧数据无法
可靠解析时采用 fail-safe 审核。事件中的 `pre_allocation:*` 表示记录的是分配前
候选或策略命中的分组，而不是事后声称已经选中的渠道分组。滚动升级期间旧用户
缓存缺少 `group_id` 时同样按 fail-safe 审核；用户分组变化会失效整条缓存，避免
分组名称和稳定 ID 不一致。

Realtime 对 `session.update`、用户 `conversation.item.create`、
`response.create` 等文本字段逐帧审核。客户端帧在通过前不得写入上游，缓冲与
转发必须保持原顺序；二进制音频帧不解析、不送 Guard，并按原帧类型和字节内容
转发。WebSocket 的二进制消息类型本身不代表音频：如果二进制负载是合法 JSON
对象，仍按普通 Realtime 事件提取和审计，防止通过帧类型绕过文本门禁。

为了保证风险首帧不产生渠道或上游连接副作用，启用审计且命中分组范围的客户端
必须先发送 `session.update`、`conversation.item.create`、`response.create`
或其他首个控制帧；实现不会为了等待上游 `session.created` 而提前选择渠道。
首个 JSON 控制帧之前到达的原始二进制音频会有界缓冲，控制帧通过后再按接收顺序
写入上游。首轮缓冲上限取部署请求体上限与 16 MiB 中较小值，且最多 1024 帧；
超过上限会以 Realtime 错误事件和 1009 关闭码拒绝，避免空帧或音频流耗尽内存。
客户端必须在 WebSocket 升级后 30 秒内送达首个 JSON 控制帧，超时返回错误事件并以
1008 关闭，防止连接在现有渠道与模型限流之前无限占用资源。
首轮通过后的畸形客户端 JSON 帧会返回标准 Realtime 错误事件并以 1007 关闭，
不会写入上游；Guard 阻断或 Guard 故障仍分别使用 4403 或 1013。
未命中审计分组或关闭模式的连接会显式跳过后续逐帧审计，避免渠道分配完成后
重新启用门禁。

稳定错误码如下：

- `prompt_guard_blocked`：HTTP 403，Realtime 关闭码 4403。
- `prompt_guard_unavailable`：HTTP 503，Realtime 关闭码 1013。
- `prompt_guard_invalid_response`：HTTP 503，Realtime 关闭码 1013。

异步模式把加密提示词和任务原子写入主数据库，Worker 直接轮询数据库；当前
实现通过数据库轮询运行，不依赖 Redis 保存任务、明文或正确性状态；Redis 唤醒
和配置失效通知只是未来可选优化。异步提取、入队或配置解密失败只增加丢弃指标，
不得改变主请求结果。

## 数据与任务契约

配置、节点、任务、事件和队列容量使用专用数据表。事件新增 `source`、`stage` 与
`prompt_available`，来源固定为 `prompt_guard`、`sensitive_word` 或
`upstream_policy`。JSON 字段统一以 TEXT 保存，
通过 `common.Marshal`、`common.Unmarshal` 等封装读写。大密文字段在 MySQL
使用 LONGTEXT，在 SQLite 与 PostgreSQL 使用 TEXT，以容纳 65536 个 Unicode
字符加密和 Base64 编码后的数据。任务状态为
`queued`、`processing`、`retry`、`done`、`failed`，领取和完成均校验
`claim_version` 与租约；多分片评估期间定时续租，续租丢失即取消旧 Worker 的
Guard 调用。队列、分页和删除兼容 SQLite、MySQL 5.7.8+、PostgreSQL 9.6+。
事件使用内部 `prompt_cipher_kind` 区分“直接提示词密文”和“失败任务负载密文”；
任务负载还携带固定格式标识。详情读取只按这两个显式标记解包，禁止通过尝试解析
用户正文 JSON 来猜测密文用途。

默认参数：Worker 4 个、队列容量 32768、Guard 超时 3000ms、Unicode 单片
4000 字符、最多重试 3 次、同步全局并发 64、单节点并发 16。持久化文本最多
65536 个 Unicode 字符，超限时记录截断标识、完整字符数和完整 SHA-256。
异步 Worker 仅对 Guard 明确标记为可重试的故障执行有界退避；非法响应及其他
不可重试错误在首次领取后直接终结为 `failed`，并在任务和事件中记录稳定错误码。

同步模式会先创建带加密正文的 `pending` 事件，再调用 Guard；通过且策略未开启
Safe 事件保存时删除该待审事件，阻断或故障事件则保留结果。异步任务失败也按当前
配置的保留天数清理，不使用固定的默认 TTL。删除筛选会拒绝负数 ID 或时间参数，
模型层对空条件删除同样拒绝，防止错误请求退化成全表删除。

Qwen3Guard 结果严格解析唯一的 `Safety:` 和 `Categories:` 行，支持暴力、
非暴力违法、性内容、PII、自杀自残、不道德行为、政治敏感、版权侵权、越狱
攻击九类风险。一次评估使用首个启用节点的超时作为总预算，所有分片和节点故障
切换共享该期限；只有可重试故障才按优先级切换，非法 Guard 响应不切换。未知安全
状态、重复字段和额外正文仍返回 `prompt_guard_invalid_response`；未知分类会被
归一化后以不可逆的 `unknown:<sha256 前缀>` 形式写入 `UnknownCategories`，不保存
原始未知文本。`Unsafe` 且包含未知分类（或没有可识别分类）按 fail-closed 阻断，
避免新版本 Guard 增加风险类别后绕过门禁。

事件详情中的 `UnknownCategories` 仅用于 Root 排查模型版本差异，永不回传原始分类
文本；其哈希输入为规范化后的类别标识。

## 管理 API

以下接口统一位于 `/api/security-audit`，并使用 `RootAuth`：

- `GET /config`、`PUT /config`
- `GET /builtin-policy`、`PUT /builtin-policy`
- `POST /endpoints/probe`
- `GET /runtime`
- `GET /events`
- `GET /events/:id`、`DELETE /events/:id`
- `POST /events/batch-delete`
- `POST /events/delete-preview`
- `POST /events/delete-by-filter`

内置策略页只通过专用 Root-only 的 `/api/security-audit/builtin-policy` 读取和保存。
接口底层继续沿用 `CheckSensitiveEnabled`、`CheckSensitiveOnPromptEnabled`、
`SensitiveRules`、`SensitiveRuleChannelIds` 等既有 Option，不复制配置。`PUT` 必须
携带 `expected_version`，并在同一数据库事务中通过 CAS 更新内置审计开关和全部
屏蔽词配置；冲突返回 HTTP 409。旧 `SensitiveWords` 会作为有效规则显示并在首次
保存时迁移为结构化 `SensitiveRules`，原 Option 保留不清空，避免页面保存隐式删除
用户数据。系统设置中的旧入口在两套前端移除，防止同一配置出现两个管理入口。

配置保存必须携带 `expected_version`，版本冲突返回 HTTP 409。节点令牌更新只允许
`token_action=keep|replace|clear`：`replace` 必须携带非空 `token`，`keep` 和
`clear` 禁止携带 `token`，接口不接受旧的 `clear_token` 字段，也永不返回令牌
明文或密文。保存配置或探测使用 `keep` 时，只有目标地址与已保存节点地址一致才会
复用旧令牌；修改节点地址必须显式 `replace` 或 `clear`，避免把旧令牌发送到新地址。原文详情、
配置写入、探测和删除还必须通过敏感操作验证并限流，响应使用
`Cache-Control: no-store`。

按筛选删除必须先预览；预览返回匹配数量、快照最大 ID、筛选哈希和五分钟确认
令牌。确认令牌使用显式配置的稳定 `CRYPTO_SECRET` 派生签名密钥，并绑定发起
预览的 Root 管理员 ID；未配置密钥时不得签发或验证。实际删除只处理快照内
数据，避免删除预览后新增事件。

## 页面与兼容性

- Default：`/security-audit`
- Classic：`/console/security-audit`

页面包含概览、审计事件、内置策略、Guard 节点、审计策略五个页内标签。侧栏入口与
渠道、用户、日志同级，仅 Root 可见；不注册扩展 manifest，不新增系统设置页面。
原系统设置“屏蔽词”区块迁移到本页且不保留重复入口。Guard
节点标签负责节点增删改、优先级、令牌状态和连通性探测；按节点生效的超时与
Unicode 分片大小统一在审计策略标签编辑，避免与策略参数分散管理。

数据库迁移只新增表和索引，默认关闭时不改变现有转发行为。回滚时先切换为
`off` 并停止 Worker，历史表和事件保留，任何物理删除都必须另行备份和确认。

## 验证要求

- 覆盖三种模式、九类解析、Unicode 分片、节点故障切换、加密、配置 CAS、队列
  容量、任务领取、租约回收、重试、保留期和删除确认令牌。
- 覆盖屏蔽词 request/response 的 block/mask 事件、流式去重、无
  `CRYPTO_SECRET` 元数据事件，以及 HTTP/SSE/Realtime 对精确 `cyber_policy`
  的识别和普通错误不误报。
- 阻断、不可用和非法响应必须断言渠道、计费及上游调用次数均为零。
- 验证 SQLite、MySQL、PostgreSQL 查询兼容性以及无 Redis 场景。
- Default、Classic 均验证 Root 入口、直达权限、空态、错误态和移动端布局。
- 本地手工测试固定使用 `scripts/local-test.ps1`、3000/3001 端口和
  `tmp-local-v10101.db`。

模型包提供可选的真实数据库集成测试：分别设置 `TEST_MYSQL_DSN` 和
`TEST_POSTGRES_DSN` 后运行 `go test ./model -run '^TestPromptAuditIntegration'`。
测试只接受尚无安全审计表的空测试库，覆盖迁移、配置 CAS、队列领取与完成、
服务端分页及两种删除路径；完成后会移除本次创建的五张测试表。

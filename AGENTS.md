# AGENTS.md

给改这段代码的人。只记当前行为里、改错就会让登录失败或对不上已有用户的约束。变更记在 git 提交里，不要往这里追加日记，也不要写部署和环境。

## 兼容

`pom.xml` 的 `keycloak.version` 是 26.8.1。这套源码只编译 Keycloak 26.5–26.8.1，Java 17。一套源码不能同时过 26.4 和 26.5，要兼容旧版就另开分支。

两处 SPI 断裂：

- 26.4 起，`callback.error(String)` 变成 `callback.error(IdentityProviderModel, String)`。调用处传 `getConfig()`。
- 26.5 起，`IdentityProvider.AuthenticationCallback` 移到 `UserAuthenticationIdentityProvider.AuthenticationCallback`。

26.5+ 的 `BrokeredIdentityContext` 会拒绝 disabled 的 IdP。测试里 `new IdentityProviderModel()` 之后必须 `setEnabled(true)`。

## 回调

`callback()` 必须返回 `AbstractOAuth2IdentityProvider.Endpoint` 的子类。Keycloak 26.8 把 `/broker/{alias}/endpoint` 当子资源定位器：直接 `return Response`，或在这个 jar 里新写一个没被索引的 `@GET`，浏览器得到 **405**，容器日志没有 ERROR。

jar 里必须有 `META-INF/jandex.idx`（`jandex-maven-plugin` 已配）。依赖都是 `provided`，不要把 Keycloak 打进 jar。

## 飞书不是标准 OIDC

授权地址由 `createAuthorizationUrl()` 拼：`client_id`、`redirect_uri`、`response_type=code`，有 state 和 prompt 才加。**不要加 `scope`。** `getDefaultScope()` 仍返回 `user_info`，但授权地址不用它。README 流程图里的 `scope=user_info` 是旧的，不要按那张图改代码。飞书不认 `user_info` 这个 scope 名，传了会拒绝整次授权。

换 token 用 JSON body（`client_id`、`client_secret`、`grant_type`、`code`、`redirect_uri`），不是 form。响应是 `{code,msg,data}`，`access_token` 在 `data` 里，没有 `id_token`。不要改回 Keycloak 内置 OIDC 的 form 交换。

`redirect_uri` 用 `getBaseUri()` 拼成 `realms/{realm}/broker/{alias}/endpoint`，授权和换 token 必须是同一个值。`getBaseUri()` 跟着转发头走；头不对时它会变成内网地址，飞书以 `redirect_uri` 不匹配拒绝。

## 身份主键

`buildIdentity()` 的 broker user id，也是 username：`union_id` → `open_id` → `sub`。`name` 只进 firstName，lastName 保持 null。改主键顺序会让已有 federated link 对不上，再次登录会再建一个用户。

`migrateFederatedIdentityLink()` 只做 `open_id` → `union_id` 的一次性迁移。先删旧链接再加新链接，顺序反了会撞唯一约束。

`IdentityProviderModel.isStoreToken()` 等开关是 `Boolean`，后台没点过就是 `null`。用 `Boolean.TRUE.equals(...)`，不要拆箱。

## 属性

映射器只复制写死的字段名单。不在名单里的 key（包括 `enterprise_email`）会被丢掉。字段缺失时调用 `removeAttribute`，同名的手工属性也会被清掉。

`getField()` 把空串和纯空白当成没有。`buildIdentity()` 只在 email 非空时 `setEmail`。不要用 email 做匹配键。

`pickAvatar()` 没有被登录路径调用。头像只以 `feishu_avatar_*` 属性存在，不会写进用户 profile。

`getCompatibleProviders()` 匹配的是 factory id `feishu`，不是 IdP alias。不要为了 alias 改这个数组。

## 日志

`FEISHU_DEBUG` 只有去空白后等于 `1` 或 `true`（忽略大小写）时，才打印 `user_info` 正文。其他值保持沉默。token 响应带 `access_token`，不要打印。

## 验证

`mvn test` 必须全绿。现有测试只覆盖解析和 `buildIdentity` 等本地逻辑，不起 Keycloak，也不打飞书。改完确认 jar 里仍有 `META-INF/jandex.idx`。

# AD / Kerberos / 委派 / 容器 / K8s 速查

> 目标：补齐偏实战渗透的高频知识，帮助离线环境下快速建立攻击面图。

---

## 1. Active Directory / Kerberos

## 1.1 先画图
- 域名
- DC
- 用户/计算机账户
- 组关系
- SPN
- 信任关系
- 委派配置

## 1.2 Kerberos 高频攻击面
- AS-REP roasting
- Kerberoasting
- 委派滥用
- 凭据转储后横向
- SPN / 票据 / PAC / 约束条件问题

## 1.3 比赛中最实用顺序
1. 找低权限可枚举信息
2. 找可 roast 账户
3. 找委派与高权限服务账户
4. 找 ACL / 组关系异常
5. 找能否横向到 DC 或管理主机

---

## 2. 委派

### 三类核心记忆
- Unconstrained Delegation
- Constrained Delegation
- Resource-Based Constrained Delegation

### 比赛中重点
- 不要背定义，重点看：**谁可以代表谁，去访问什么服务**
- RBCD 常与机器账户、ACL 控制、写属性能力绑定

---

## 3. 容器 / Docker

## 3.1 高频检查点
- 容器内是否挂载 docker.sock
- 是否特权容器
- 是否挂载宿主机目录
- capability 是否过大
- 可否进入 host namespace

## 3.2 容器逃逸思路
1. 找 socket / daemon 控制面
2. 找宿主机挂载
3. 找特权与 capability
4. 找内核接口和 namespace 逃逸点

---

## 4. Kubernetes

## 4.1 高频检查点
- ServiceAccount token
- kubeconfig
- API Server 可达性
- RBAC 权限
- 挂载 secret / configmap
- 节点权限和 pod 创建权限

## 4.2 利用优先级
1. 先拿 token / config
2. 枚举权限
3. 若能创建 pod，尝试挂宿主机或高权限 pod
4. 若能读 secret，继续横向
5. 关注 etcd / 控制面暴露

---

## 5. 统一方法论

这些题的共性是：
- **身份关系图** 比单点漏洞更重要
- **谁信任谁、谁能代表谁、谁能调谁的 API** 是核心

### 统一提问法
1. 我现在是什么身份
2. 我能读取哪些凭据/票据/令牌
3. 我能代表谁
4. 我能创建什么对象
5. 我能把控制面权限转成宿主机/域管权限吗

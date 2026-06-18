---
category: "OSINT"
tags: ["开源情报", "社交媒体", "图像地理位置", "域名WHOIS", "Google Dork", "Shodan替代", "EXIF GPS", "照片取证", "互联网档案馆"]
difficulty: "中级"
---

# 08 - OSINT开源情报搜集

## 1. 概述

OSINT（Open Source Intelligence）在CTF MISC中考验选手利用公开信息源获取情报的能力。典型题目场景：根据一张照片找到拍摄地点；通过残缺的社交媒体截图获取账号信息；利用域名信息追溯攻击者身份；根据建筑物照片查找坐标等。

断网场景下，OSINT考察的是**事前积累的数据库**、**本地缓存的数据分析能力**，以及**从题目提供的文件本身提取信息**。关键的断网替代方案：EXIF/GPS坐标本地分析、本地字典/Dork库、预缓存的搜索引擎结果、离线地图数据。

## 2. 核心原理

### 2.1 EXIF元数据分析

数码照片（尤其是智能手机拍摄）包含丰富的EXIF（Exchangeable Image File Format）数据：

```bash
exiftool photo.jpg
# 关键字段:
# GPS Latitude / Longitude / Altitude: GPS坐标
# GPS Position: 综合位置
# Camera Model Name: 设备型号
# Date/Time Original: 拍摄时间
# Create Date: 创建时间
# Make: 设备厂商 (Apple, Samsung, Huawei, Canon...)
# Software: 处理软件
# Image Description: 图片描述 (可能含提示)
# Artist / Copyright: 作者/版权 (可能含提示)
# Lens ID / Focal Length: 镜头信息
```

**GPS坐标格式转换**:
```
EXIF GPS格式: deg min' sec" 方向
  例: 39 deg 54' 26.35" N, 116 deg 23' 50.40" E
  十进制: 39 + 54/60 + 26.35/3600 = 39.90732
  即: 39.90732° N, 116.39733° E → 北京故宫
```

**坐标提取Python脚本**:
```python
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import sys

def get_gps_info(image_path):
    """提取图片GPS信息"""
    img = Image.open(image_path)
    exif_data = img._getexif()
    if not exif_data:
        print("No EXIF data")
        return None
    
    # 获取GPS标签
    for tag_id, value in exif_data.items():
        tag = TAGS.get(tag_id, tag_id)
        if tag == "GPSInfo":
            gps_info = {}
            for gps_tag_id, gps_value in value.items():
                gps_tag = GPSTAGS.get(gps_tag_id, gps_tag_id)
                gps_info[gps_tag] = gps_value
            return gps_info
    return None

def gps_to_decimal(gps_info):
    """将GPS EXIF数据转为十进制坐标"""
    def dms_to_dd(dms, ref):
        degrees = dms[0]
        minutes = dms[1]
        seconds = dms[2]
        dd = float(degrees) + float(minutes)/60 + float(seconds)/3600
        if ref in ['S', 'W']:
            dd = -dd
        return dd
    
    lat = dms_to_dd(gps_info['GPSLatitude'], gps_info['GPSLatitudeRef'])
    lon = dms_to_dd(gps_info['GPSLongitude'], gps_info['GPSLongitudeRef'])
    return lat, lon

# 使用
gps = get_gps_info('photo.jpg')
if gps and 'GPSLatitude' in gps:
    lat, lon = gps_to_decimal(gps)
    print(f'Location: {lat:.6f}, {lon:.6f}')
    print(f'Google Maps: https://maps.google.com/?q={lat},{lon}')
    # 但由于断网，需要本地离线地图
```

### 2.2 图像OSINT分析维度

一张照片可分析的信息层级：

| 层级 | 分析内容 | 提取方法 |
|------|---------|---------|
| L1 元数据 | EXIF/GPS/时间戳/设备 | exiftool |
| L2 视觉内容 | 建筑物/地标/车牌/语言 | 视觉分析 |
| L3 水印/LOGO | 社交媒体水印/原作者 | 图像裁剪对比 |
| L4 隐写层 | LSB/频谱隐写 | 图片隐写工具 |
| L5 文件名 | 命名规则/时间戳 | 字符串分析 |
| L6 图片文件结构 | Thumbnail/嵌入缩略图 | exiftool -b |

### 2.3 域名与WHOIS情报

WHOIS记录包含：
- **注册人/注册机构**: Registrant Name/Organization
- **注册时间/到期时间**: Creation Date / Expiry Date
- **DNS服务器**: Name Servers
- **联系信息**: Email, Phone, Address

CTF中的WHOIS相关题型：
- 根据域名找注册人线索
- 历史WHOIS记录对比
- 多个域名的关联分析

断网替代方案：
- 本地WHOIS文本数据库（`whois.nic.xx`的缓存）
- 通过题目提供的线索（往往出题人会把WHOIS的一部分信息嵌在题目中）
- 已知TLD的格式模板

### 2.4 Google Dork (Google Hacking)

Google Dork利用Google搜索引擎的高级搜索语法。断网时无法使用线上Google，但可以本地化Dork作为分析知识：

```
经典Dork语法:
  site:example.com             # 限定域名
  intitle:"Index of"           # 标题包含
  inurl:admin                  # URL包含
  filetype:php                 # 文件类型
  intext:"password"            # 正文包含
  ext:log                      # 扩展名
  cache:url                    # 缓存快照 (在线)
  link:url                     # 反向链接

组合示例:
  site:ctfcompetition.com filetype:pdf "confidential"
  intitle:"index of" "backup" site:.gov
  inurl:admin intitle:login
```

**本地Dork备忘脚本** (断网环境下帮助设计搜索策略):
```python
# 常见目标模式
DORK_PATTERNS = {
    "敏感文件": 'site:{domain} filetype:{ext} {keyword}',
    "目录遍历": 'intitle:"Index of" site:{domain}',
    "备份文件": 'site:{domain} ext:bak OR ext:backup OR ext:old',
    "配置文件": 'site:{domain} ext:conf OR ext:config OR ext:ini OR ext:yml',
    "日志文件": 'site:{domain} ext:log intext:{keyword}',
    "数据库文件": 'site:{domain} ext:sql OR ext:db OR ext:mdb',
    "子域名发现": 'site:*{domain} -www',
}
```

### 2.5 Shodan离线替代

Shodan是互联网设备搜索引擎。断网时无法使用在线Shodan，但可以使用：
- 本地预扫描的Nmap结果
- Shodan的Banner指纹规则

**本地Banner分析**（模拟Shodan）:
```python
# 常见的服务Banner指纹识别
SERVICE_FINGERPRINTS = {
    'Apache': ['Apache/', 'httpd'],
    'nginx': ['nginx/', 'ngx_http'],
    'IIS': ['Microsoft-IIS/', 'Microsoft IIS'],
    'Tomcat': ['Apache-Coyote/', 'Apache Tomcat'],
    'OpenSSH': ['OpenSSH_', 'SSH-2.0-OpenSSH'],
    'vsftpd': ['vsFTPd'],
    'ProFTPD': ['ProFTPD'],
    'MySQL': ['mysql_native_password', 'MySQL'],
    'PostgreSQL': ['PostgreSQL'],
    'Redis': ['redis_version'],
    'MongoDB': ['MongoDB'],
    'Elasticsearch': ['Elasticsearch'],
}
```

## 3. 关键工具与命令

### 3.1 照片元数据提取

```bash
# exiftool (最重要)
exiftool photo.jpg                              # 全部数据
exiftool -gps* photo.jpg                        # 只看GPS
exiftool -common photo.jpg                      # 常用元数据
exiftool -b -ThumbnailImage photo.jpg > thumb.jpg  # 提取缩略图
exiftool -json photo.jpg                        # JSON格式输出

# 批量GPS提取
exiftool -filename -gpslatitude -gpslongitude *.jpg > gps_coords.csv
```

### 3.2 离线经纬度定位

虽然没有Google Maps API，但可以使用：
- **本地OpenStreetMap数据**（预下载文件）
- **离线坐标反查表**（预先准备的各大城市坐标范围）

```python
# 离线城市坐标粗查表
CITY_COORDS = {
    "北京": (39.9042, 116.4074),
    "上海": (31.2304, 121.4737),
    "广州": (23.1291, 113.2644),
    "深圳": (22.5431, 114.0579),
    "成都": (30.5728, 104.0668),
    "杭州": (30.2741, 120.1551),
    "南京": (32.0603, 118.7969),
    "武汉": (30.5928, 114.3055),
    "西安": (34.3416, 108.9398),
    "重庆": (29.4316, 106.9123),
    # ... 可扩展更多
}

def find_nearest_city(lat, lon):
    """根据坐标找最近的城市"""
    import math
    nearest = None
    min_dist = float('inf')
    for city, (clat, clon) in CITY_COORDS.items():
        dist = math.sqrt((lat-clat)**2 + (lon-clon)**2)
        if dist < min_dist:
            min_dist = dist
            nearest = city
    return nearest, min_dist
```

### 3.3 社交媒体痕迹分析

即使断网，题目可能直接提供社交媒体页面的截图或HTML源码。分析维度：
- 用户名/ID模式识别（如：用户可能跨平台使用相同ID）
- 头像/背景图的EXIF数据
- 个人资料中的可识别信息（地点、组织、URL）
- 关注/粉丝列表（社交图谱）
- 发帖内容的时间模式

### 3.4 图片比较工具

```bash
# 比较两张图片的差异
compare img1.jpg img2.jpg diff.png       # ImageMagick

# 计算图片哈希（感知哈希/perceptual hash）
# 查找到相同场景的不同照片（可能是不同版本）
identify -verbose img.jpg | grep -i sign  # ImageMagick signature

# 搜索相似图片（本地pHASH数据库）
python -c "
from PIL import Image
import imagehash  # needs: pip install imagehash
hash1 = imagehash.phash(Image.open('img1.jpg'))
hash2 = imagehash.phash(Image.open('img2.jpg'))
print(f'Distance: {hash1 - hash2}')  # ≤5 通常表示相似
"
```

## 4. 常见误区与注意事项

### 误区1: 忘记检查EXIF中的GPS
很多选手打开图片只"看"了，忘记检查EXIF。**任何CTF中的照片题，第一步永远是`exiftool photo.jpg`。**

### 误区2: 只看主图不看缩略图
数码相机和手机在JPEG中可能嵌入缩略图（Thumbnail）。缩略图可能是原始未裁剪版本，包含更多信息。**`exiftool -b -ThumbnailImage` 提取缩略图。**

### 误区3: 坐标格式不转换
GPS坐标在EXIF中的格式是度分秒(DMS)，不是十进制。直接用DMS搜地图会定位错误。

### 误区4: 忽视设备和时间信息
- 设备型号可以推断年代（如Camera Model: "iPhone 4S" 推断照片年代为2011-2013）
- 拍摄时间可以结合其他线索（如：照片中的报纸日期）
- 软件版本号可能关联到特定漏洞（非OSINT但可能相关）

### 误区5: 语言线索忽略
照片中的文字/标志/路牌使用的语言是最直接的定位线索。中文简体→大陆，中文繁体→台湾/香港，日文假名→日本。路牌的格式和颜色也随国家/地区不同。

### 误区6: 想当然地依赖网络搜索
断网OSINT的关键是**从题目提供的数据中充分提取信息**。出题人往往在文件名、EXIF字段、图片内容中给出了足够线索。

## 5. 实战示例

### 示例1: 根据照片找拍摄位置

```
场景: 一张城市街景照片

步骤:
1. exiftool photo.jpg | grep GPS
   输出:
   GPS Latitude: 39 deg 54' 26.35" N
   GPS Longitude: 116 deg 23' 50.40" E
2. 转换坐标: 39.90732° N, 116.39733° E
3. 对照本地坐标表 -> 北京故宫区域
4. GPS坐标即flag: flag{39.90732_116.39733}
   或 flag{beijing_forbidden_city}
```

### 示例2: 社交媒体截图ID关联

```
场景: 给出两个不同平台的用户资料截图

步骤:
1. 分析截图的内容:
   - 平台A: 用户名 "shadow_hacker_42", 个人简介 "CTF enthusiast..."
   - 平台B: 用户名 "shadow42", 相同头像，个人简介只有Link
2. 提取共同点:
   - "shadow" 关键词
   - "42" 数字
   - 相同头像
   - 相同的Email域名 (@hackermail.ctf)
3. 推断这是同一人
4. 两个用户名拼接或取交集得到flag
```

### 示例3: Google Dork式本地文件搜索

```
场景: 给出一个网站的目录结构（本地文件），需要找到隐藏的后台

步骤:
1. 列出目录结构:
   find . -type f | head -100
2. 搜索可疑文件:
   find . -name "*.bak" -o -name "*.backup" -o -name "*.old"
   find . -name "*admin*" -o -name "*login*"
   grep -r "password" --include="*.txt" .
3. 发现 admin/.htpasswd 或 config.php.bak
4. 提取flag
```

### 示例4: 缩略图中的隐藏信息

```
场景: 一张裁剪过的JPEG照片，EXIF被清除

步骤:
1. exiftool photo.jpg
   输出: 大部分EXIF字段已删除（被stripped）
2. exiftool -b -ThumbnailImage photo.jpg > thumb.jpg
3. file thumb.jpg
   输出: JPEG image data
4. 打开thumb.jpg查看
   发现缩略图是**未裁剪的原始照片**，包含更多画面
   画面中有flag写在一块告示牌上
5. 获得flag
```

### 示例5: 文件名时间戳推理解密

```
场景: 多个文件，文件名都是Unix时间戳

步骤:
1. ls
   output: 1710691200.txt  1710777600.txt  1710864000.txt
2. date -d @1710691200
   输出: 2024年3月17日 星期日 UTC 16:00:00
3. 取时间戳中的特定数位作为密码
4. 或者对比文件创建顺序，找规律
5. 解密或拼接内容 -> flag
```

## 6. 相关知识点

### 6.1 Steganography vs OSINT 的交叉

有些题目会结合图片隐写和地理位置信息。例如：
- LSB隐写中嵌入的是GPS坐标
- 图片本身是一个地标，EXIF中含另一个地标的坐标
- 一系列照片的GPS连线在地图上拼出flag

### 6.2 社交媒体平台API残留

虽然断网不能用API，但题目中的JSON/XML数据可能模拟了Twitter/GitHub/Instagram的API响应格式。了解这些格式有助于解析数据：
- **Twitter API v1.1/v2** JSON结构
- **GitHub REST API** 响应格式
- **Instagram** 基本数据字段

### 6.3 常见密码/ID生成规律

许多CTFer的ID/密码有规律：
- 名字+数字后缀 (shadow42, admin123)
- leetspeak (l33t, h4x0r, p@ssw0rd)
- 键盘模式 (qwerty, 1qaz2wsx)
- CTF平台ID (可能会跨平台一致)

### 6.4 地标数据库离线版

可预先准备的数据：
- IATA机场代码 → 城市
- 国家顶级域名 ccTLD (.cn→中国, .jp→日本, .kr→韩国)
- 主要城市电话区号
- 汽车车牌格式 (各省/直辖市/国家的格式)
- 货币符号

### 6.5 小参数模型辅助

1. **图片内容描述**: 向模型描述图片中的建筑物/标志/文字特征，模型可推测地理位置
2. **ID/用户名模式分析**: "发现用户名列表: alice_wonderland, bob_builder, charlie_chocolate..." → 模型分析命名规律
3. **时间线索推理**: 给出文件时间戳组合，模型推断事件时间线
4. **语言/文字识别**: 图片中文字的语言判断（即使不能直接OCR）
5. **社交工程模式**: 分析社交平台截图中个人简介的用词习惯

---

**OSINT快速自查清单**:
- [ ] `exiftool` 检查所有元数据字段
- [ ] GPS坐标提取与转换（度分秒→十进制）
- [ ] 提取缩略图 (`exiftool -b -ThumbnailImage`)
- [ ] 文件名分析（模式/时间戳/编码信息）
- [ ] 文件创建/修改时间
- [ ] 图片中的文字/标识/车牌/路牌
- [ ] 设备型号/软件版本
- [ ] 用户ID在文件中的其他出现位置
- [ ] 多图片之间的关联/差异对比
- [ ] 预置字典匹配坐标/城市/ID

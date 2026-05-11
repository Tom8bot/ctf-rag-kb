# Linux 与命令速查

## 1. 文件与文本
```bash
file target
strings -a -n 4 target
xxd target | head
hexdump -C target | head
binwalk -e target
exiftool target
stat target
sha256sum target
md5sum target
```

```bash
grep -R "flag" .
grep -Rni "password\|token\|secret" .
find . -type f | sort
find . -type f -name "*.php"
find . -perm -4000 2>/dev/null
```

```bash
cut -d: -f1 file
awk '{print $1}' file
sed -n '1,20p' file
sort file | uniq -c | sort -nr | head
tr -d '
' < file
```

---

## 2. 编码与摘要
```bash
python3 - << 'PY'
import base64
print(base64.b64decode('SGVsbG8='))
PY
```

```bash
echo -n 'test' | xxd -p
echo 74657374 | xxd -r -p
echo -n 'test' | base64
echo 'dGVzdA==' | base64 -d
```

```bash
openssl dgst -md5 file
openssl dgst -sha256 file
openssl enc -aes-128-cbc -d -in enc.bin -out dec.bin -K <hexkey> -iv <hexiv>
```

---

## 3. ELF / Pwn / 调试
```bash
checksec --file=./pwn
ldd ./pwn
readelf -a ./pwn | less
objdump -d -Mintel ./pwn | less
nm -an ./pwn | less
ROPgadget --binary ./pwn | head
```

```bash
gdb -q ./pwn
pattern create 300
pattern offset <value>
```

### 常见 gdb 操作
```gdb
b *main
r
ni
si
x/20gx $rsp
info registers
vmmap
```

---

## 4. 流量与网络
```bash
tshark -r file.pcap | head
tshark -r file.pcap -Y 'http' -T fields -e http.host -e http.request.uri
strings file.pcap | less
nc host port
curl -i http://host/
python3 -m http.server 8000
```

---

## 5. 压缩与取证
```bash
zipinfo file.zip
7z l file.zip
7z x file.zip
foremost file
steghide info file.jpg
stegseek file.jpg wordlist.txt
pdfinfo file.pdf
qpdf --qdf --object-streams=disable in.pdf out.pdf
```

---

## 6. 实战习惯
- 所有重要输出重定向保存：`cmd | tee out.txt`
- 对比两个响应：`diff -u a.txt b.txt`
- 先看头尾：`head` / `tail`
- 大文件先 `strings`、`file`、`binwalk`，不要盲目打开
- 对每个题目录一个工作目录：源码 / 脚本 / 输出 / 笔记 分开

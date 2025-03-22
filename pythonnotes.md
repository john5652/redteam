# Python Cheatsheet

A comprehensive, beginner-to-advanced Python reference.

---

## 🧱 Syntax and Fundamentals
- Python uses **indentation** instead of `{}` to define blocks.
- Indentation must be consistent within a block.

```python
def test():
    print("test")
    print("test")
```

---

## 🔤 Variables and Data Types
```python
name = "Ellerion"
print(type(name))  # <class 'str'>
```

### Number Types
```python
int_num = 1
float_num = 1.0
complex_num = 3.14j
hex_num = 0xa   # 10
octal_num = 0o10  # 8
```

### Number Utilities
```python
abs(-4)            # 4
round(8.4)         # 8
bin(8)             # '0b1000'
hex(8)             # '0x8'
```

---

## 🧵 Strings
```python
"string", 'string', '''multi
line'''
"I\'m a string"  # Escaping
"\x41"           # Hex: 'A'
```

### Operations
```python
"a" * 10
"string" in "I'm a string"
string1.startswith("I")
string1.upper()
string1.lower()
password.strip()
password.replace("!", "?")
string.split(",")
```

### Formatting
```python
"Length: " + str(len(s))
"{} chars".format(len(s))
f"{len(s)} chars"
f"{num:.2f}"  # 2 decimals
f"{num:x}"   # Hex
"%d chars!" % len(s)
```

---

## 📦 Data Structures

### Tuples (Immutable)
```python
tuple_items = ("item1", "item2")
tuple_items.index("item1")
item1, item2 = tuple_items
```

### Lists (Mutable)
```python
list1 = ["A", "B", 1]
list1.append("Z")
list1.pop()
list1.sort(reverse=True)
```

### Dictionaries
```python
dict1 = {"a": 1, "b": 2}
dict1["a"]
dict1.get("a")
dict1.keys(), dict1.values(), dict1.items()
```

### Sets (Unordered, No Duplicates)
```python
set1 = {"a", "b"}
set1.add("c")
set1.update(["x", "y"])
set1.remove("a")
set1.discard("z")
```

---

## 🔁 Loops

### While Loop
```python
a = 0
while a < 5:
    a += 1
```

### For Loop
```python
for i in range(5):
    print(i)
```

### Loop Control
```python
break, continue, pass
```

### Nested Loops
```python
for i in range(2):
    for j in range(2):
        print(i, j)
```

---

## 🔀 Conditionals
```python
if a == b:
    ...
elif a > b:
    ...
else:
    ...
```

### Ternary
```python
"Yes" if a == b else "No"
```

---

## 📁 File Handling

### Open Modes
- `r`: Read
- `w`: Write (overwrite)
- `a`: Append
- `x`: Create
- `b`, `t`: Binary/Text

### Reading/Writing
```python
with open("file.txt", "r") as f:
    print(f.read())

with open("file.txt", "w") as f:
    f.write("Hello")
```

### Iterating Lines
```python
with open("file.txt") as f:
    for line in f:
        print(line.strip())
```

---

## 🎯 Functions
```python
def greet(name):
    return f"Hello {name}"

def add(*args):
    return sum(args)

def display(**kwargs):
    for k, v in kwargs.items(): print(k, v)
```

### Lambda
```python
lambda x: x + 2
map(lambda x: x*2, nums)
sorted(list, key=lambda x: x['age'])
```

---

## 🔄 Comprehensions
```python
[x for x in range(5)]
[x for x in range(5) if x % 2 == 0]
[[i+j for j in range(3)] for i in range(3)]
{x for x in "abcabc"}  # Set
```

---

## 📦 Modules

### Virtual Environments
```bash
python3 -m venv env
source env/bin/activate
deactivate
```

### Pip
```bash
pip install requests
pip freeze > requirements.txt
```

---

## 🧰 sys Module
```python
import sys
print(sys.argv)
sys.exit(1)
```

### Progress Bar Example
```python
for i in range(50):
    sys.stdout.write(f"\r{i}%")
    sys.stdout.flush()
```

---

## 🌐 requests Module
```python
import requests

res = requests.get("http://httpbin.org/get")
print(res.status_code)
print(res.json())
```

### POST
```python
requests.post("url", data={"key": "value"})
```

### Headers, Auth, Params
```python
requests.get("url", headers={...}, params={...}, auth=(user, pass))
```

---

## 🔐 pwntools Basics
```python
from pwn import *

p = process("/bin/sh")
p.sendline("echo hi")
p.interactive()
```

### Other
```python
cyclic(50)
cyclic_find("laaa")
shellcraft.sh()
p32(0x1337)
```

---

## ✅ Tip
If you're learning, try each block in a REPL or Python file!

---

_Last updated: March 2025._


---
title: "ثغرات تجاوز سعة المخزن المؤقت (Buffer Overflow): الشرح الشامل والحماية"
date: 2025-11-01
draft: false
author: "مكتبة قرطبة"
description: "دليل تفصيلي لفهم ثغرات Buffer Overflow، آليات استغلالها، وطرق الحماية منها"
tags: ["Buffer Overflow", "ثغرات أمنية", "استغلال الثغرات", "البرمجة الآمنة"]
categories: ["أمن المعلومات", "الثغرات الأمنية"]
---

# ثغرات تجاوز سعة المخزن المؤقت (Buffer Overflow): الشرح الشامل والحماية

## مقدمة

تُعد ثغرات تجاوز سعة المخزن المؤقت (Buffer Overflow أو Buffer Overrun) من أقدم وأخطر أنواع الثغرات الأمنية في عالم البرمجيات. على الرغم من معرفتنا بهذه الثغرات منذ عقود، إلا أنها لا تزال تُستغل في هجمات حقيقية وتشكل تهديداً أمنياً جدياً للأنظمة والتطبيقات.

في هذا المقال، سنستكشف بعمق آلية عمل هذه الثغرات، أنواعها المختلفة، طرق استغلالها، وأهم الآليات الدفاعية الحديثة للحماية منها.

## ما هو Buffer Overflow؟

### التعريف الأساسي

**المخزن المؤقت (Buffer)** هو منطقة محددة في الذاكرة تُستخدم لتخزين البيانات مؤقتاً أثناء نقلها من مكان لآخر. يحدث **تجاوز السعة (Overflow)** عندما يتم كتابة بيانات تتجاوز الحجم المخصص للمخزن المؤقت، مما يؤدي إلى الكتابة فوق مناطق ذاكرة مجاورة.

### مثال توضيحي بسيط

تخيل كوباً سعته 250 مل:
- إذا صببت 250 مل من الماء → الكوب ممتلئ بشكل طبيعي ✓
- إذا صببت 500 مل من الماء → الماء يفيض ويؤثر على ما حوله ✗

هذا بالضبط ما يحدث في الذاكرة عند تجاوز سعة المخزن المؤقت.

## البنية التقنية: كيف يحدث Buffer Overflow؟

### هيكل الذاكرة في البرامج

عند تشغيل برنامج، يُخصص له مساحة في الذاكرة تُقسم إلى عدة أقسام:

```
┌─────────────────────┐  ← عناوين ذاكرة عليا (High Memory)
│   Stack (المكدس)    │  ← متغيرات محلية، عناوين الرجوع
├─────────────────────┤
│        ↓            │
│                     │
│   (مساحة حرة)       │
│                     │
│        ↑            │
├─────────────────────┤
│    Heap (الكومة)    │  ← ذاكرة ديناميكية مخصصة
├─────────────────────┤
│   BSS Segment       │  ← متغيرات غير مُهيّأة
├─────────────────────┤
│   Data Segment      │  ← متغيرات مُهيّأة وثابتة
├─────────────────────┤
│   Text/Code         │  ← كود البرنامج (تعليمات)
└─────────────────────┘  ← عناوين ذاكرة دنيا (Low Memory)
```

### المكدس (Stack) وأهميته

المكدس هو المنطقة الأكثر استهدافاً في هجمات Buffer Overflow، ويحتوي على:

```c
┌────────────────────────┐  ← قمة المكدس (Stack Top)
│  متغيرات محلية (Local) │
├────────────────────────┤
│  Saved Frame Pointer   │  ← مؤشر الإطار المحفوظ (EBP)
├────────────────────────┤
│  Return Address (RET)  │  ← عنوان الرجوع (أهم هدف!)
├────────────────────────┤
│  معاملات الدالة        │
└────────────────────────┘
```

**عنوان الرجوع (Return Address)** هو العنوان الذي يعود إليه البرنامج بعد انتهاء تنفيذ الدالة الحالية. إذا تم تعديله، يمكن توجيه البرنامج لتنفيذ كود خبيث!

## أنواع Buffer Overflow

### 1. Stack-Based Buffer Overflow

يحدث في المكدس ويستهدف عادةً:
- المتغيرات المحلية
- عناوين الرجوع (Return Addresses)
- مؤشرات الإطارات (Frame Pointers)

### 2. Heap-Based Buffer Overflow

يحدث في الكومة (Heap) ويستهدف:
- البيانات المخصصة ديناميكياً (malloc, new)
- بيانات التحكم في الذاكرة (Heap metadata)

### 3. Off-by-One Overflow

خطأ برمجي يكتب بايت واحد خارج حدود المخزن:
```c
char buffer[10];
for(int i = 0; i <= 10; i++) {  // خطأ: يجب أن يكون i < 10
    buffer[i] = 'A';
}
```

## أمثلة عملية على الثغرات

### مثال 1: الكود الضعيف (Vulnerable Code)

```c
#include <stdio.h>
#include <string.h>

void vulnerable_function(char *user_input) {
    char buffer[64];  // مخزن بحجم 64 بايت فقط

    // خطر! لا يوجد فحص لطول المدخل
    strcpy(buffer, user_input);

    printf("تم نسخ البيانات: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if(argc > 1) {
        vulnerable_function(argv[1]);
    }
    return 0;
}
```

**المشكلة:** استخدام `strcpy()` بدون فحص طول المدخل يسمح بتجاوز حدود المخزن.

### مثال 2: الاستغلال (Exploitation)

```bash
# إنشاء مدخل يحتوي على 100 حرف 'A'
./vulnerable_program $(python -c 'print "A" * 100')

# النتيجة: Segmentation Fault (انهيار البرنامج)
# السبب: تم الكتابة فوق عنوان الرجوع!
```

### مثال 3: الكود الآمن (Secure Code)

```c
#include <stdio.h>
#include <string.h>

void secure_function(char *user_input) {
    char buffer[64];

    // استخدام دالة آمنة مع فحص الطول
    strncpy(buffer, user_input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';  // ضمان إنهاء السلسلة

    printf("تم نسخ البيانات بأمان: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if(argc > 1) {
        secure_function(argv[1]);
    }
    return 0;
}
```

## آليات الاستغلال (Exploitation Techniques)

### 1. Shellcode Injection

حقن كود خبيث (Shellcode) في الذاكرة وتوجيه البرنامج لتنفيذه:

```python
# مثال على هيكل الاستغلال (مبسّط)
payload = ""
payload += "A" * 64           # ملء المخزن المؤقت
payload += "B" * 4            # الكتابة فوق Saved EBP
payload += "\x10\x20\x30\x40" # عنوان Shellcode (Return Address)
payload += shellcode          # الكود الخبيث
```

### 2. Return-to-libc Attack

بدلاً من حقن كود جديد، يتم استخدام دوال موجودة في المكتبات:

```
Return Address → system() function
Arguments      → "/bin/sh"
```

### 3. Return Oriented Programming (ROP)

تقنية متقدمة تستخدم "gadgets" (قطع صغيرة من كود موجود):

```assembly
; ROP Gadget مثال
pop eax    ; استخراج قيمة من المكدس
ret        ; العودة (تنفيذ Gadget التالي)
```

## دراسة حالة: ثغرة حقيقية

### Code Red Worm (2001)

**الهدف:** خوادم Microsoft IIS

**الثغرة:** Buffer overflow في ISAPI extension

**التأثير:**
- أصاب أكثر من 359,000 خادم
- خسائر تُقدر بـ $2.6 مليار
- هجمات DDoS على whitehouse.gov

**السبب التقني:**
```c
// الكود الضعيف في IIS
char buffer[256];
// لا يوجد فحص لطول URL
memcpy(buffer, url, url_length);
```

### Heartbleed (2014)

**الهدف:** OpenSSL

**النوع:** Heap-based buffer over-read

**التأثير:**
- تسريب ذاكرة خوادم آمنة
- تسريب مفاتيح خاصة ومعلومات حساسة
- أثر على 17% من خوادم HTTPS

## آليات الحماية الحديثة

### 1. ASLR (Address Space Layout Randomization)

**الفكرة:** توزيع عشوائي لمواقع الذاكرة

```
# قبل ASLR - عناوين ثابتة
Stack:  0xbffff000
Heap:   0x08048000
libc:   0x40000000

# بعد ASLR - عناوين عشوائية في كل تشغيل
Stack:  0xbf8a3000
Heap:   0x09123000
libc:   0x4f2a0000
```

**الهدف:** جعل من الصعب التنبؤ بعناوين الذاكرة

### 2. DEP / NX (Data Execution Prevention / No-eXecute)

**الفكرة:** منع تنفيذ الكود من مناطق البيانات

```
Stack:  RW-  (قراءة، كتابة، لا تنفيذ)
Heap:   RW-  (قراءة، كتابة، لا تنفيذ)
Code:   R-X  (قراءة، لا كتابة، تنفيذ)
```

**الهدف:** منع تنفيذ Shellcode المحقون

### 3. Stack Canaries / Stack Guards

**الفكرة:** وضع قيمة سرية قبل عنوان الرجوع

```c
┌────────────────────────┐
│  متغيرات محلية         │
├────────────────────────┤
│  Stack Canary (قيمة عشوائية) │  ← القيمة المحمية
├────────────────────────┤
│  Saved EBP             │
├────────────────────────┤
│  Return Address        │
└────────────────────────┘

// فحص Canary قبل العودة
if (canary_value != original_canary) {
    abort();  // إيقاف البرنامج
}
```

**التطبيق في GCC:**
```bash
gcc -fstack-protector-all program.c -o program
```

### 4. SafeSEH (Safe Structured Exception Handling)

**للحماية من:** استغلال Exception Handlers في Windows

### 5. Control Flow Integrity (CFI)

**الفكرة:** التحقق من صحة تدفق التنفيذ

```c
// قبل كل قفزة غير مباشرة
if (!is_valid_target(target_address)) {
    abort();
}
```

## أفضل الممارسات البرمجية للحماية

### 1. استخدام دوال آمنة

| الدالة غير الآمنة | الدالة الآمنة | الملاحظات |
|-------------------|---------------|-----------|
| `strcpy()`        | `strncpy()`, `strlcpy()` | تحديد طول النسخ |
| `strcat()`        | `strncat()`, `strlcat()` | تحديد طول الإلحاق |
| `gets()`          | `fgets()`     | `gets()` خطرة جداً! |
| `sprintf()`       | `snprintf()`  | تحديد حجم المخزن |
| `scanf("%s")`     | `scanf("%Ns")` | تحديد العدد الأقصى |

### 2. فحص حدود المصفوفات

```c
// جيد ✓
for(int i = 0; i < ARRAY_SIZE; i++) {
    array[i] = value;
}

// سيئ ✗
for(int i = 0; i <= ARRAY_SIZE; i++) {
    array[i] = value;  // Off-by-one error
}
```

### 3. التحقق من صحة المدخلات

```c
void process_input(char *input, size_t input_length) {
    char buffer[MAX_SIZE];

    // فحص الطول قبل المعالجة
    if (input_length >= MAX_SIZE) {
        fprintf(stderr, "خطأ: المدخل كبير جداً\n");
        return;
    }

    memcpy(buffer, input, input_length);
    buffer[input_length] = '\0';
}
```

### 4. استخدام لغات آمنة للذاكرة

اللغات التي توفر حماية تلقائية:
- **Rust**: Ownership system يمنع Buffer overflow
- **Go**: Bounds checking تلقائي
- **Python, Java, C#**: Managed memory

```rust
// Rust - آمن بالتصميم
fn safe_function(input: &str) {
    let mut buffer = String::with_capacity(64);
    buffer.push_str(input);  // آمن، لا يمكن تجاوز الحدود
}
```

### 5. استخدام أدوات التحليل الثابت

```bash
# مثال: استخدام Valgrind للكشف عن مشاكل الذاكرة
valgrind --leak-check=full --show-leak-kinds=all ./program

# مثال: استخدام AddressSanitizer
gcc -fsanitize=address -g program.c -o program
./program
```

## اختبار وجود الثغرات

### أدوات الفحص

#### 1. Fuzzing Tools

```bash
# AFL (American Fuzzy Lop)
afl-gcc vulnerable_program.c -o vulnerable_program
afl-fuzz -i input_dir -o output_dir ./vulnerable_program @@
```

#### 2. GDB للتحليل

```bash
# فحص برنامج باستخدام GDB
gdb ./vulnerable_program

(gdb) run $(python -c 'print "A" * 100')
# مراقبة انهيار البرنامج

(gdb) info registers
# فحص محتوى المسجلات

(gdb) x/100x $esp
# فحص محتوى المكدس
```

#### 3. Pattern Generation

```python
# إنشاء نمط فريد للعثور على offset
from pwn import *

pattern = cyclic(200)
print(pattern)

# بعد الانهيار، استخدام:
cyclic_find(0x61616161)  # العثور على موقع الكتابة فوق RET
```

## الحماية على مستوى النظام

### Linux

```bash
# تفعيل ASLR
echo 2 | sudo tee /proc/sys/kernel/randomize_va_space

# فحص حالة الحماية
checksec --file=./program

# إعدادات المترجم الآمنة
gcc -fstack-protector-strong \
    -D_FORTIFY_SOURCE=2 \
    -Wformat -Werror=format-security \
    -pie -fPIE \
    program.c -o program
```

### Windows

```powershell
# تفعيل DEP
bcdedit /set {current} nx AlwaysOn

# فحص حماية ASLR
Get-ProcessMitigation -Name program.exe
```

## الخلاصة والتوصيات

### النقاط الرئيسية

1. **الفهم الأساسي ضروري**: فهم آلية عمل Buffer Overflow أساس لكتابة كود آمن
2. **الوقاية أفضل من العلاج**: استخدام ممارسات البرمجة الآمنة منذ البداية
3. **الحماية متعددة الطبقات**: استخدام أكثر من آلية حماية (Defense in Depth)
4. **التحديث المستمر**: متابعة التحديثات الأمنية وتطبيقها فوراً

### توصيات للمطورين

- ✓ استخدم دوال آمنة دائماً
- ✓ فعّل جميع آليات الحماية عند الترجمة
- ✓ راجع الكود بحثاً عن عمليات نسخ غير آمنة
- ✓ استخدم أدوات التحليل الثابت والديناميكي
- ✓ تجنب الافتراضات حول حجم المدخلات
- ✓ فحص جميع الحدود قبل عمليات الكتابة

### توصيات لمسؤولي الأنظمة

- ✓ فعّل ASLR و DEP على مستوى النظام
- ✓ طبق التحديثات الأمنية بانتظام
- ✓ استخدم أدوات مراقبة الثغرات
- ✓ نفذ سياسات Least Privilege
- ✓ راقب السجلات بحثاً عن محاولات استغلال

## المراجع والمصادر

### كتب ومراجع علمية

1. **Aleph One (1996)**. "Smashing The Stack For Fun And Profit". Phrack Magazine, Issue 49.

2. **Erickson, J. (2008)**. "Hacking: The Art of Exploitation, 2nd Edition". No Starch Press.

3. **OWASP Foundation**. "Buffer Overflow". OWASP Testing Guide v4.

4. **Seacord, R. (2013)**. "Secure Coding in C and C++, 2nd Edition". Addison-Wesley.

5. **Koziol, J., et al. (2004)**. "The Shellcoder's Handbook: Discovering and Exploiting Security Holes". Wiley.

### معايير ومواصفات

6. **CERT Coding Standards**:
   - SEI CERT C Coding Standard
   - SEI CERT C++ Coding Standard

7. **CWE (Common Weakness Enumeration)**:
   - CWE-120: Buffer Copy without Checking Size of Input
   - CWE-121: Stack-based Buffer Overflow
   - CWE-122: Heap-based Buffer Overflow

8. **CVE Database**: Common Vulnerabilities and Exposures

### مصادر إضافية

9. **Microsoft Security Development Lifecycle (SDL)**. "Buffer Overrun Prevention".

10. **NIST Special Publication 800-53**: Security and Privacy Controls.

11. **Exploit Database** (exploit-db.com): أمثلة واقعية على استغلالات Buffer Overflow

12. **Phrack Magazine**: مقالات تقنية متقدمة حول استغلال الثغرات

---

*تاريخ النشر: نوفمبر 2025*
*تصنيف: الثغرات الأمنية | البرمجة الآمنة*
*المؤلف: فريق مكتبة قرطبة للأمن السيبراني*

**تحذير:** المعلومات الواردة في هذا المقال للأغراض التعليمية فقط. استخدام هذه المعلومات لاستغلال أنظمة دون إذن يُعد جريمة يعاقب عليها القانون.

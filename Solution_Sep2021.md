# NEFU 2021.9 CTF WriteUp


第一次有幸参加东林的CTF比赛，非常开心，学到了很多东西。

**自身缺点** ：
- Wireshark操作不熟练，找flag有点“黑傻掰苞米”。

**get到的技能**  ：

- 图片信息隐写的各种方法及工具。
- ZIP伪加密原理

-------------------
## PHP

### coverage(变量覆盖)

如题，考察变量覆盖
```php=
<?php

highlight_file(__FILE__);
include 'flag.php';

$pps = "may the force";
$nonono = "be with you";
$obs = 'pps';

/* 变量的初始化，注意到obs变量的值是pps变量的名字，即等价于
 * => $$obs = ${$obs} = $pps = "may the force"(缺省情况)
 * 显然"may the force"以及其余变量的内容是完全无用的，考虑修改
 */

foreach($_POST as $a => $b){
    $$a = $b;
}

/* 功能函数1
 * 遍历POST的内容
 * 并取其左值为变量名,右值为内容
 * 即: Input:a = b, val(a) = b
 */

foreach($_GET as $a => $b){
    $$a = $$b;
}

/* 功能函数2
 * 遍历GET的内容
 * 并取其内容为变量名
 * 即: Input:a = b, val(a) = val(b)
 */

foreach($_GET as $a => $b){
    if($_GET['flag'] === $a && $a !== 'flag'){
        exit($obs);
    }
}

/* 作恶函数1
 * 遍历GET的内容
 * 防止Payload为 flag = a && a = something_except_flag 的情况
 */

if(!isset($_GET['flag']) && !isset($_POST['flag'])){
    exit($pps);
}

/* 作恶函数2
 * 遍历GET,POST的内容
 * 防止Payload中未给flag赋值
 * Solution: 必须给flag赋值 或 pps为flag
 */

if($_POST['flag'] === 'flag'  || $_GET['flag'] === 'flag'){
    exit($nonono);
}

/* 作恶函数3
 * 遍历 GET,POST 中 flag 的内容
 * Solution: 均不可flag = flag
 * 或 nonono为 flag 的同时 不给flag赋值(pass 上一个 if)
 */

echo "your flag: ".$flag;

/* Solution: Pass掉所有 if 且 flag 未被修改
 */
//Output:flag{**************}
```

初始结果为`may the force`，表示程序以pps为返回值退出，要顺利向下到flag，就要满足作恶函数2的条件:给flag赋值，但由于flag内容为唯一答案且不可知，所以自此函数往下不考虑。

现在我们有两种思路：
- A. 将flag的值赋给obs输出，并满足作恶函数1的退出条件
- B. 将flag的值赋给pps输出，并不满足作恶函数1的退出条件，但满足2的退出条件

--------------------

#### Plan A:

>感谢 **b477eRy** 指正纰漏处

- 1. `obs = flag`前不可对`flag`赋值
- 2. Payload中需有`obs = flag`
- 3. 不可pass掉作恶函数1

先考虑`obs = flag`后的可行性:

##### **输入:**

```
obs = flag
```

##### **功能函数1:**

```
   val(obs) = flag
=> pps      = flag
```
flag值被复制到了pps

##### **功能函数2:**

```
   val(pps) = val(flag)
=> flag     = flag{********}
```
无意义

现在我们处于**Line35**，答案储存于`pps`中，计划输出`pps`。
作恶函数1通过。
来到**Line46**，需要对`flag`赋值以输出`pps`。
考虑在`obs = flag`前或后补充Payload: `flag = ?`。

我们在 **?** 处补充变量的目的是利用`$$b`来访问以 **?** 为名称的变量内容，并将其赋给`$$flag`
无论前后，写入的变量名是`flag{********}`，无关紧要，所以 **?** 爱填啥填啥。
只需让 **Line36** 的条件得到满足即可，看定义可知：`? = obs`

此时，输出为`pps`。因为`obs`的缺省内容为`pps`。
利用功能函数1，新建Payload:
```php
$$obs = 'obs'
$pps = 'obs'
```
~~相当于构建了一个映射，对`pps`的操作被嫁接给了`obs`。
最后直接输出`obs`就是正确答案。~~
#### **大错特错，写`obs = * `就行，在 Line 36 满足条件就直接跳了。**

##### Vars:
| obs |               pps               |    flag{\*}     |
|:---:|:-------------------------------:|:---------------:|
| pps | ~~N/A~~ -> ~~flag~~ -> flag{\*} | ~~obs~~ -> flag |

---------------------------
这里如果Payload中`obs=flag`在先的话:

good func1:
```php
$pps = 'flag'
```

good func2:
```php
$pps = 'flag{*******}'
……
```

`obs`没人碰，输出就是flag。

##### Vars:
| obs      | pps  |      flag{\*}       |
| -------- |:----:|:-------------------:|
| flag{\*} | flag | ~~obs~~ -> flag{\*} |

--------------------------

#### Plan B:

- 1. `pps = flag`前不可对`flag`赋值
- 2. Payload中需有`pps = flag`
- 3. 必须pass掉作恶函数1

先考虑`pps = flag`后的可行性:

##### **输入:**

```
pps = flag
```

##### **功能函数1:**

```
   val(pps)        = flag
=> "may the force" = flag
```
无意义

##### **功能函数2:**

```
   val(pps)        = val(flag)
=> "may the force" = flag{********}
```

由于`$"may the force"`无法输出，无意义

最后程序以接收Payload时的

```
pps = flag
```

退出，pps未受干扰。
返回值即为我们要的flag。

### MD5
```php=
<?
highlight_file(__FILE__);
include("F1Lg.php");
if (!isset($_GET['a']) || !isset($_GET['b'])) {
    die("no no no");
}
if ($_GET['a'] == $_GET['b']){
    die("no no no");
}
if (md5($_GET['a']) !== md5($_GET['b'])) {
    die("no no no");
}
echo $flag;
```
get两个变量，
当他们值不同但MD5相同时输出答案。

#### 方法1：MD5碰撞

给定一个前缀，使用`fastcoll`快速地生成一对MD5碰撞的数值。
再将二进制文件转为php字符串的格式即可
这里我的Payload是：
```
a = 11451419198101926081719171107%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%E7%E8%87v%F0%F1%B6%D1%90%95%84P%89%B5%8C8%FF%AByb%A35%2F%84%1D2%84%F1%0B%28%15%EB%02%05%C3%E2%5D%226%9F%EB%CD%CA%23%A2%3B%40B%403%BE%B9%06%14%C6%29%C5A%24%5E%B8%7E%D7%94%DA%C6%1E%CE%8E%A9%92%BA%A9%97%E1-%A8%92%E8%B21%F5%1A%B6%AE%DB%FC%FB%F288U%D0f%B5%ED%E9%E7%B14%2B%7C%84%88%FEc%F99%8Bp%EE%5C%C50%3B%2Bn%CA%C3L%AD%97a%FB%A0%23%946
b = 11451419198101926081719171107%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%E7%E8%87v%F0%F1%B6%D1%90%95%84P%89%B5%8C8%FF%ABy%E2%A35%2F%84%1D2%84%F1%0B%28%15%EB%02%05%C3%E2%5D%226%9F%EB%CD%CA%23%A2%BB%40B%403%BE%B9%06%14%C6%29%C5A%24%DE%B8%7E%D7%94%DA%C6%1E%CE%8E%A9%92%BA%A9%97%E1-%A8%92%E8%B21%F5%1A6%AE%DB%FC%FB%F288U%D0f%B5%ED%E9%E7%B14%2B%7C%84%88%FEc%F99%8B%F0%ED%5C%C50%3B%2Bn%CA%C3L%AD%97a%7B%A0%23%946
```

#### 方法2：利用PHP md5()函数的错误返回

`md5(string,raw)` 

> “如果成功则返回已计算的 MD5 散列，如果失败则返回 FALSE。”
> \- [PHP Manual](https://www.php.net/manual/zh/function.md5.php)


|  参数  | 描述                                 |
|:------:|:------------------------------------ |
| string | 必需。规定要计算的字符串。           |
|  raw   | 可选。规定十六进制或二进制输出格式： |
|        | TRUE - 原始 16 字符二进制格式        |
|        | FALSE - 默认。32 字符十六进制数      |

构造Payload：
`a[1] = 1 & b[1] = 2`
即可。

## Reverse

### easyre

IDA看，发现`a=b`就输出，flag也写出来了。

### reverse1

```=
                mov     edi, offset format ; "input the flag:"
                mov     eax, 0
                call    _printf
                lea     rax, [rbp+s2]
                mov     rsi, rax
                mov     edi, offset a20s ; "%20s"
                mov     eax, 0
                call    ___isoc99_scanf
                lea     rax, [rbp+s2]
                mov     rsi, rax        ; s2
                mov     edi, offset flag ; s1
                call    _strcmp
                test    eax, eax
                jz      short loc_400854
                mov     edi, offset s   ; "wrong flag!"
                call    _puts
                jmp     short loc_40085E
; ---------------------------------------------------------------------------

loc_400854:                             ; CODE XREF: main+C9↑j
                mov     edi, offset aThisIsTheRight ; "this is the right flag!"
                call    _puts

loc_40085E:                             ; CODE XREF: main+D5↑j
                mov     rdx, [rbp+var_18]
                xor     rdx, fs:28h
                jz      short loc_400872
                call    ___stack_chk_fail
; ---------------------------------------------------------------------------
```

可以看到**Line13**处若`_strcmp`比对成功后就跳转到成功提示了。
所以查看下我们输入数据的比对对象。
```=
flag            db 7Bh ->'{'            ; DATA XREF: main+34↑r
                                        ; main+44↑r ...
aHackingForFun  db 'hacking_for_fun}',0
```
一个很诱人的字符串映入眼帘，但不要着急，前面还有引用
```=
loc_4007AC:                             ; CODE XREF: main+72↓j
                mov     eax, [rbp+var_38]
                cdqe
                movzx   eax, flag[rax]
                cmp     al, 69h ; 'i'
                jz      short loc_4007CC
                mov     eax, [rbp+var_38]
                cdqe
                movzx   eax, flag[rax]
                cmp     al, 72h ; 'r'
                jnz     short loc_4007D8
loc_4007CC:                             ; CODE XREF: main+3D↑j
                mov     eax, [rbp+var_38]
                cdqe
                mov     flag[rax], 31h ; '1'
loc_4007D8:                             ; CODE XREF: main+4D↑j
                add     [rbp+var_38], 1
loc_4007DC:                             ; CODE XREF: main+2D↑j
                mov     eax, [rbp+var_38]
                movsxd  rbx, eax
                mov     edi, offset flag ; s
                call    _strlen
                cmp     rbx, rax
                jbe     short loc_4007AC
```
可以看出是预处理阶段把flag字符串里的`'i'`和`'r'`替换成`'1'`。
我们也替换一下，就可以得到flag。

### JAVA
一开始使用IDA查看，栈内操作比较复杂，再加上优化较多，看不出来。
后来使用`JD-GUI`，得到代码。
```Java=
import java.util.ArrayList;
import java.util.Scanner;

public class Reverse {
  public static void main(String[] args) {
    Scanner s = new Scanner(System.in);
    System.out.println("Please input the flag );
    String str = s.next();
    System.out.println("Your input is );
    System.out.println(str);
    char[] stringArr = str.toCharArray();
    Encrypt(stringArr);
  }
  
  public static void Encrypt(char[] arr) {
    ArrayList<Integer> Resultlist = new ArrayList<>();
    for (int i = 0; i < arr.length; i++) {
      int result = arr[i] + 64 ^ 0x20;
      Resultlist.add(Integer.valueOf(result));
    } 
    int[] KEY = { 
        180, 136, 137, 147, 191, 137, 147, 191, 148, 136, 
        133, 191, 134, 140, 129, 135, 191, 65 };
    ArrayList<Integer> KEYList = new ArrayList<>();
    for (int j = 0; j < KEY.length; j++)
      KEYList.add(Integer.valueOf(KEY[j])); 
    System.out.println("Result:");
    if (Resultlist.equals(KEYList)) {
      System.out.println("Congratulations);
    } else {
      System.err.println("Error);
    } 
  }
}
```
Line17,18对字符串进行了加密操作。
一开始想当然的写出原文生成代码
```cpp
#include <iostream>
#include <cstring>
#include <string>
#include <iomanip>

using namespace std;

int s[] = {
	180, 136, 137, 147, 191, 137, 147, 191, 148, 136,
	133, 191, 134, 140, 129, 135, 191, 65
};

int main()
{
	for (int i = 0; i <= end(s) - begin(s); i++)
		cout << (char)(s[i] - 64 ^ 0x20);
	return 0;
}
```
把加号改成减号就好，
但是此题通过之后才发现`+ -`的优先级比异或的高
就代表：
在位运算下，
$$
\begin{array}{l}
(a - b) \oplus c = (a \oplus c) - b{\kern 1pt} {\kern 1pt} {\kern 1pt} {\kern 1pt} {\kern 1pt} {\kern 1pt} {\kern 1pt} {\kern 1pt} {\kern 1pt} {\kern 1pt} {\kern 1pt} {\kern 1pt} {\kern 1pt} (b > c, & b \vee c = 0)\\
对于\forall c \in {\rm{R}}恒成立
\end{array}
$$
合理，~~但是我不会证明~~ 我又会了。
c的那位会来回翻转，没有系数的话偶数次**XOR**操作就可。
但需要说明的是需要括号内的条件防止操作进位破坏其他高位数据。

### 高质量题目2
`IDA`打开发现UPX版权信息，脱壳后一眼就拔旗。

### reverse2
用于比对的字符串
```x86asm
.data:0000000000601080 flag            db '{'                  ; DATA XREF: main+34↑r
.data:0000000000601080                                         ; main+44↑r ...
.data:0000000000601081 aHackingForFun  db 'hacking_for_fun}',0
```
替换处理
```cpp=
int __cdecl main(int argc, const char **argv, const char **envp)
{
    int stat_loc;        // [rsp+4h] [rbp-3Ch] BYREF
    int i;               // [rsp+8h] [rbp-38h]
    __pid_t pid;         // [rsp+Ch] [rbp-34h]
    char s2[24];         // [rsp+10h] [rbp-30h] BYREF
    unsigned __int64 v8; // [rsp+28h] [rbp-18h]

    v8 = __readfsqword(0x28u);
    pid = fork();
    if (pid)
    {
        waitpid(pid, &stat_loc, 0);
    }
    else
    {
        //这里替换'r','i'为'1'
        for (i = 0; i <= strlen(&flag); ++i)
        {
            if (*(&flag + i) == 'i' || *(&flag + i) == 'r')
                *(&flag + i) = '1';
        }
    }
    printf("input the flag:");
    __isoc99_scanf("%20s", s2);
    if (!strcmp(&flag, s2))
        return puts("this is the right flag!");
    else
        return puts("wrong flag!");
}
```
后，可得到flag。

### 你疑惑吗
拖进IDA
```cpp=
int __cdecl main(int argc, const char **argv, const char **envp)
{
    int i;         // [rsp+2Ch] [rbp-124h]
    char __b[264]; // [rsp+40h] [rbp-110h] BYREF

    memset(__b, 0, 0x100uLL);
    printf("Input your flag:\n");
    get_line(__b, 256LL);
    if (strlen(__b) != 33)
        goto LABEL_7;
    for (i = 1; i < 33; ++i)
        __b[i] ^= __b[i - 1];
    if (!strncmp(__b, global, 0x21uLL))
        printf("Success");
    else
    LABEL_7:
        printf("Failed");
    return 0;
}
```
**Line11-12**可见使用异或递推。
由于异或的
$$
(A\;{\mathop{\rm XOR}\nolimits} \;B)\;{\mathop{\rm XOR}\nolimits} \; = \;A
$$
性质
写出反推的Code:
```cpp=
#include <iostream>
#include <cstring>
using namespace std;

char s[] = {0x66, 0x0A, 0x6B, 0x0C, 0x77, 0x26, 0x4F, 0x2E, 0x40, 0x11, 0x78, 0x0D, 0x5A, 0x3B, 0x55, 0x11, 0x70, 0x19, 0x46, 0x1F, 0x76, 0x22, 0x4D, 0x23, 0x44, 0x0E, 0x67, 0x6, 0x68, 0x0F, 0x47, 0x32, 0x4F, 0x0};

int main()
{
	int len = strlen(s);
	cout << len << endl;
	for (int i = 1; i < strlen(s); i++)
		for (int j = 0; j <= i - 1; j++)
			s[i] ^= s[j];
	cout << s << endl;
	return 0;
}
```
## MISC

> Misc 是切入 CTF 竞赛领域、培养兴趣的最佳入口。Misc 考察基本知识，对安全技能的各个层面都有不同程度的涉及，可以在很大程度上启发思维。    —— [CTF Wiki](https://ctf-wiki.org/misc/introduction/)

### 电线鲨鱼

找到一个几个可疑的login请求，追踪下，password即是flag。 

### 金三胖
播放器逐帧播放即可，`He11o`别看成`Hello`就好。(论编程字体的重要性)

### zip
题面过于清爽，觉得不能是爆破题。
WinHex看了一下发现是伪加密，两个`09 00`改掉就好。

### 奇怪的图片
刚看到图片，觉得白色空间占比过大，觉得可能用类白色的灰色藏了些文字，PS查看后否定。
几个图片隐写工具都没有结果。想到了傅里叶变换方面，但高射炮不需打蚊子 ~~（其实是我不会）~~。

Google了下原图发现大白被裁了？掏出WinHex改了下高度，庐山真面目自现。

### QRCode
此题做的憋屈，前面一路流畅，zip隐写，7zip自动打开就好。
看到`"secret is here"`之后又看到了`4numbers.txt`的加密文件，第一反应竟然是把`"here"`转成数字，尝试n种规则不行。最后被迫上爆破拿到flag了，但好像题正解就是爆破的。~~（发散思维的坏处）~~

## Crypto

### Enigma

### 凯撒密码
首先尝试朴素的凯撒密码，枚举位移量，但没有通顺的解密结果。
观察到一个开头为 **f** 的字符串，推测`string[i]`的位移量加权为`i`，于是cpp枚举，找到了flag。
``` cpp
#include <iostream>
#include <cstring>
#include <string>

using namespace std;

char s[] = "afZ_r9VYfScOeO_UL^RWUc";

int main()
{
	cout << 'r' - 'a' + 1 << endl;
	for (int i = -24; i <= -18; i++)
	{
		for (int j = 0; j < strlen(s); j++)
		{
//			cout << (char)((s[j] + i) % 128);
//			cout << (char)((s[j] + i + 26) % 128);
			cout << (char)((s[j] + i + j + 26) % 128);
		}
		cout << endl;
	}
	return 0;
}
```

### 古典密码
一眼看出Minecraft同款的标准银河字母。剩下的两个查猪圈密码的时候带出来了。查表初步得到`"FGCPFLIRTUASYON"`的密文，看到非连续的`"FLAG"`字串，推测栅栏加密，枚举每组字数，得到3，解密得flag。



## 联系方式
- QQ: 2120935182
- NEFU CTF平台: sfc9982

---------
感谢阅读这篇文章。

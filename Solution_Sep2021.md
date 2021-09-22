# NEFU 2021.9 CTF 题解


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

## MISC

> Misc 是切入 CTF 竞赛领域、培养兴趣的最佳入口。Misc 考察基本知识，对安全技能的各个层面都有不同程度的涉及，可以在很大程度上启发思维。    —— [CTF Wiki](https://ctf-wiki.org/misc/introduction/)

### 电线鲨鱼

找到一个几个可疑的login请求，追踪下，password即是flag。 

### 金三胖
播放器逐帧播放即可，`He11o`别看成`Hello`就好。(论编程字体的重要性)

### zip
题面过于清爽，觉得不能是爆破题。
WinHex看了一下发现是伪加密，两个`0900`改掉就好。

### 奇怪的图片
刚看到图片，觉得白色空间占比过大，觉得可能用类白色的灰色藏了些文字，PS查看后否定。
几个图片隐写工具都没有结果。想到了傅里叶变换方面，但高射炮不需打蚊子 ~~（其实是我不会）~~。

Google了下原图发现大白被裁了？掏出WinHex改了下高度，庐山真面目自现。

### QRCode
此题做的憋屈，前面一路流畅，zip隐写，7zip自动打开就好。
看到`"secret is here"`之后又看到了`4numbers.txt`的加密文件，第一反应竟然是把`"here"`转成数字，尝试n种规则不行。最后被迫上爆破拿到flag了，但好像题正解就是爆破的。~~（发散思维的坏处）~~

## Crypto

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

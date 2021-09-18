# NEFU 2021.9 CTF 题解

@(CTF题解)[CTF|隐写|RSA]

第一次有幸参加东林的CTF比赛，非常开心，学到了很多东西。

 **自身缺点** ：
- Wireshark操作不熟练，找flag有点“黑傻掰苞米”。

**get到的技能**  ：

- 图片信息隐写的各种方法及工具。
- ZIP伪加密原理

-------------------

## MISC

> Misc 是切入 CTF 竞赛领域、培养兴趣的最佳入口。Misc 考察基本知识，对安全技能的各个层面都有不同程度的涉及，可以在很大程度上启发思维。    —— [CTF Wiki](https://ctf-wiki.org/misc/introduction/)

### 电线鲨鱼

找到一个几个可以的login相关请求，追踪下，password即是flag。 

### 金三胖
播放器逐帧播放即可，`He11o`别看成`Hello`就好。(论编程字体的重要性)

### zip
题面过于清爽，觉得不能是爆破题。
WinHex看了一下，两个0900改掉就好。

### 奇怪的图片
刚看到图片，觉得白色空间占比过大，觉得可能用类白色的灰色藏了些文字，PS查看后否定。
几个图片隐写工具都没有结果。想到了傅里叶变换方面，但高射炮不需打蚊子~~（其实是我不会）~~。

Google了下原图发现大白被裁了？掏出WinHex改了下高度，庐山真面目自现。

### QRCode
此题做的憋屈，前面一路流畅，zip隐写，7zip自动打开就好。
看到`"secret is here"`之后又看到了`4numbers.txt`的加密文件，第一反应竟然是把`"here"`转成数字，尝试n种规则不行。最后被迫上爆破拿到flag了，但好像题正解就是爆破的。~~（发散思维的坏处）~~

## Crypto

### 凯撒密码
首先尝试朴素的凯撒密码，枚举位移量，但没有通顺的解密结果。
观察到一个开头为 **f** 的字符串，推测string[i]的位移量加权为i，遂cpp枚举，找到了flag。
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

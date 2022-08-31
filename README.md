# FRIDA-DEXDump


호우.. 쉬잇.. 이러면 분석을 할 수 없다!

​

분석을 하려면 원본 dex파일을 가져와야 한다. 물론 앱이 실행될 때 숨겨진 dex파일을 load하기 때문에 앱은 정상적으로 동작한다. 그럼 원본 dex파일을 추출하기 위해 시도한 나의 방법을 포스팅해본다.

​

전체적인 분석 과정은 다음과 같다.

1. JEB로 기존 소스 코드 분석, 자바 소스 코드 내에서 동적 로딩 로직 파악(확신 없이 추측만 했음)

2. unlink, remove 함수 후킹해서 StackTrace 및 BackTrace 로 동적 로딩 로직 추적

3. IDA + 동적 디버깅으로 해당 서브 루틴 분석(그러나 실패)

4. 구글링하다 frida-dexdump 발견 후 원본 dex 파일 추출 성공

5. frida-dexdump 소스 코드 분석 및 참고해서 프리다 스크립트 작성

​

세부적인 과정을 설명하기 앞서 현재 메모리 내에서 load된 dex 파일을 모두 추출해주는 frida-dexdump 링크를 아래에 남겨두겠다.

https://github.com/hluwa/FRIDA-DEXDump
[출처] [AOS][FRIDA] How to Extract Dynamic Loaded DEX File|작성자 Koo00

```bash
Java.perform(function() {
	console.error('\n[!] Let\'s Koo00 !\n');
	ExtractDexFile();
});

function ExtractDexFile() {
	console.warn('[!] Let\'s Extract ! :D');
	Process.enumerateRanges('r--').forEach(function (range) {
		try {
			if(range.file.path && (range.file.path.startsWith("/data/dalvik-cache/") || range.file.path.startsWith("/system/") || range.file.path.startsWith("/dev/"))) {
				return;
			}
			else {
				Memory.scanSync(range.base, range.size, "64 65 78 0a 30 ?? ?? 00").forEach(function (match) {
					console.log('\x1b[32m[*] file_path : ' + range.file.path + '\x1b[0m');
					var dex_addr = match.address;
					var dex_size = dex_addr.add(0x20).readUInt();
					console.log('\x1b[33m[*] dex_addr : ' + dex_addr + '\x1b[0m');
					console.log('\x1b[36m[*] dex_size : ' + dex_size + '\x1b[0m');
					
					var file = new File("/sdcard/unpack/" + dex_addr + ".dex", "wb");
					file.write(Memory.readByteArray(dex_addr, dex_size));
					file.flush();
					file.close();
				});
			}
			
		} catch (e) {}
	})
	console.warn('[!] Extract Complete ! :)');
}
[출처] [AOS][FRIDA] How to Extract Dynamic Loaded DEX File|작성자 Koo00
```


`frida-dexdump` is a frida tool to find and dump dex in memory to support security engineers in analyzing malware.

## Make Jetbrains Great Again

<p align="center">
    <img src = "https://resources.jetbrains.com/storage/products/company/brand/logos/jb_beam.png" width = 150>
    <img src = "https://resources.jetbrains.com/storage/products/company/brand/logos/PyCharm.png" width = 500>
</p>

## Features

1. Support fuzzy search broken header dex(deep search mode).
2. Compatible with all android version(frida supported).
3. One click installation, without modifying the system, easy to deploy and use.

## Installation

```
pip3 install frida-dexdump
```

## Usage

CLI arguments base on [frida-tools](https://github.com/frida/frida-tools), you can quickly dump the foreground application like this:

```
frida-dexdump -FU
```

Or specify and spawn app like this:

```
frida-dexdump -U -f com.app.pkgname
```

Additionally, you can see in `-h` that the new options provided by frida-dexdump are: 

```
-o OUTPUT, --output OUTPUT  Output folder path, default is './<appname>/'.
-d, --deep-search           Enable deep search mode.
--sleep SLEEP               Waiting times for start, spawn mode default is 5s.
```

When using, I suggest using the `-d, --deep-search` option, which may take more time, but the results will be more complete.

![screenshot](screenshot.png)

## Build and develop

```
make
```

### Requires

See [requirements.txt](https://github.com/hluwa/FRIDA-DEXDump/blob/master/requirements.txt)

## Internals

[《深入 FRIDA-DEXDump 中的矛与盾》](https://mp.weixin.qq.com/s/n2XHGhshTmvt2FhxyFfoMA)

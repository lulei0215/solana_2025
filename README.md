
## 目标

```
solana链的监听sol的充值，匹配已知的地址，处理自己的逻辑 给用户充值等
solana的转账，用户的提现，通过钱包的密码+谷歌的动态验证码 双重安全机制
```
### 原理

```
github.com/gagliardetto/solana-go的包的调用对应的监听区块的方法
加密：钱包的密码+谷歌的动态验证码 生成 wallet.json文件，后续解密完成转账
```
```
1.监听的打印记录：
solana 监听 地址组，然后判断充值 sol
go run main.go 0
****** Redis连接成功 ******
****** 从最新区块 389107557 开始监听 ******
****** 开始监听区块，起始区块: 389107557 ******
****** 监听间隔: 200 毫秒 ******
****** 快速追赶间隔: 50 毫秒 ******
****** 超快速追赶间隔: 10 毫秒 ******
****** 配置文件: addresses.json ******
****** 监控地址数量: 1 ******
****** 监控地址列表: ******
******   4RDDCh5xfBogMgGa9mcaNQVeVMF5fSnifqPWfUuNff6r ******
****** 按 Ctrl+C 停止监听 ******

****** 正常监听: 处理区块 389107557 (最新区块: 389107558) ******
****** 正常监听: 处理区块 389107558 (最新区块: 389107561) ******
****** 当前区块 389107559 落后最新区块 389107563 共 4 个区块，启动快速追赶协程 ******
****** 正常监听模式跳转到最新区块: 389107563 ******
****** 正常监听: 处理区块 389107563 (最新区块: 389107563) ******
****** 快速追赶协程开始: 从区块 389107559 追赶至 389107563 ******
****** 快速追赶: 处理区块 389107559 ******
****** 快速追赶: 处理区块 389107560 ******
****** 正常监听: 处理区块 389107564 (最新区块: 389107565) ******
****** 快速追赶: 处理区块 389107561 ******
****** 正常监听: 处理区块 389107565 (最新区块: 389107568) ******
2.
go run main.go 2 4RDDCh5xfBogMgGa9mcaNQVeVMF5fSnifqPWfUuNff6r 0.00009
钱包公钥: Huj4tvVfZJPN9jV98Zp57raFYdvoLaE9vLoGCwc22uGr
转账金额: 90000 lamports (0.000090000 SOL)
请输入钱包密码: 
✓ 密码验证成功
请输入Google Authenticator验证码: 
解密时使用的TOTP密钥: ILBF277Y2UTLEZ2DNOB6ZG2I56ZXT6OU
输入的验证码: 637729
验证TOTP - 密钥: ILBF277Y2UTLEZ2DNOB6ZG2I56ZXT6OU, 验证码: 637729
TOTP验证结果: true
解密时使用的盐: 8326c272b5208779a7029f0d50e52987
解密时使用的IV: 71943876b0f8f8bef71b5cfbcce37619
解密时生成的TOTP密钥哈希: 1d8ba61fa36e64615ab17779a0fc972ea1e77a4d54159223038008fd1fa37f48
解密出的公钥: Huj4tvVfZJPN9jV98Zp57raFYdvoLaE9vLoGCwc22uGr
期望的公钥: Huj4tvVfZJPN9jV98Zp57raFYdvoLaE9vLoGCwc22uGr
✓ TOTP验证成功
✓ 转账成功! 交易哈希: 4msLCBzcP74D8gfWYzFvfst6eUPCCM5c8sJoZ8b2CsyZavyHaEftkLgm5jjA5rDiJjz9RXhoy8us9JN5znLmu6Db
```

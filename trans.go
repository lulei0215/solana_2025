package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/ssh/terminal"
)

// 加密的私钥结构
type EncryptedWallet struct {
	EncryptedPrivateKey string `json:"encrypted_private_key"`
	PublicKey           string `json:"public_key"`
	Salt                string `json:"salt"`
	IV                  string `json:"iv"`
	EncryptedTOTPKey    string `json:"encrypted_totp_key"`
}

// 钱包管理器
type WalletManager struct {
	client *rpc.Client
	wallet *EncryptedWallet
}

// 生成RSA密钥对
func generateRSAKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

// 使用RSA公钥加密AES密钥
func encryptAESKeyWithRSA(aesKey []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, aesKey, nil)
}

// 使用RSA私钥解密AES密钥
func decryptAESKeyWithRSA(encryptedAESKey []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedAESKey, nil)
}

// 生成AES密钥
func generateAESKey(password string, salt []byte) []byte {
	hash := sha256.Sum256([]byte(password + string(salt)))
	return hash[:]
}

// 加密私钥 - 使用传入的TOTP密钥
func encryptPrivateKeyWithTOTP(privateKey *solana.PrivateKey, password string, totpSecret string) (*EncryptedWallet, error) {
	// 使用传入的TOTP密钥
	fmt.Printf("加密时使用的TOTP密钥: %s\n", totpSecret)

	// 生成随机盐和IV
	salt := make([]byte, 16)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	fmt.Printf("加密时使用的盐: %x\n", salt)
	fmt.Printf("加密时使用的IV: %x\n", iv)

	// 使用TOTP密钥加密私钥
	totpKey := generateAESKey(totpSecret, salt)
	fmt.Printf("加密时生成的TOTP密钥哈希: %x\n", totpKey)

	block, err := aes.NewCipher(totpKey)
	if err != nil {
		return nil, err
	}

	privateKeyBytes := []byte(*privateKey)
	ciphertext := make([]byte, len(privateKeyBytes))
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext, privateKeyBytes)

	// 使用密码加密TOTP密钥（用于验证密码）
	passwordKey := generateAESKey(password, salt)
	block2, err := aes.NewCipher(passwordKey)
	if err != nil {
		return nil, err
	}

	encryptedTOTPKey := make([]byte, len(totpKey))
	stream2 := cipher.NewCFBEncrypter(block2, iv)
	stream2.XORKeyStream(encryptedTOTPKey, totpKey)

	return &EncryptedWallet{
		EncryptedPrivateKey: base64.StdEncoding.EncodeToString(ciphertext),
		PublicKey:           privateKey.PublicKey().String(),
		Salt:                base64.StdEncoding.EncodeToString(salt),
		IV:                  base64.StdEncoding.EncodeToString(iv),
		EncryptedTOTPKey:    base64.StdEncoding.EncodeToString(encryptedTOTPKey),
	}, nil
}

// 验证密码（不返回私钥，只验证身份）
func (wm *WalletManager) verifyPassword(password string) error {
	// 解码数据
	salt, err := base64.StdEncoding.DecodeString(wm.wallet.Salt)
	if err != nil {
		return fmt.Errorf("钱包数据损坏")
	}

	iv, err := base64.StdEncoding.DecodeString(wm.wallet.IV)
	if err != nil {
		return fmt.Errorf("钱包数据损坏")
	}

	encryptedTOTPKey, err := base64.StdEncoding.DecodeString(wm.wallet.EncryptedTOTPKey)
	if err != nil {
		return fmt.Errorf("钱包数据损坏")
	}

	// 使用密码尝试解密TOTP密钥
	passwordKey := generateAESKey(password, salt)
	block, err := aes.NewCipher(passwordKey)
	if err != nil {
		return fmt.Errorf("密码错误")
	}

	totpKey := make([]byte, len(encryptedTOTPKey))
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(totpKey, encryptedTOTPKey)

	// 验证TOTP密钥是否有效（通过尝试解密私钥）
	ciphertext, err := base64.StdEncoding.DecodeString(wm.wallet.EncryptedPrivateKey)
	if err != nil {
		return fmt.Errorf("钱包数据损坏")
	}

	block2, err := aes.NewCipher(totpKey)
	if err != nil {
		return fmt.Errorf("密码错误")
	}

	plaintext := make([]byte, len(ciphertext))
	stream2 := cipher.NewCFBDecrypter(block2, iv)
	stream2.XORKeyStream(plaintext, ciphertext)

	// 验证解密结果长度
	if len(plaintext) != 64 {
		return fmt.Errorf("密码错误")
	}

	// 安全地验证私钥
	var isValid bool
	func() {
		defer func() {
			if r := recover(); r != nil {
				isValid = false
			}
		}()

		privateKey := solana.PrivateKey(plaintext)
		publicKey := privateKey.PublicKey()
		if publicKey.String() == wm.wallet.PublicKey {
			isValid = true
		} else {
			isValid = false
		}
	}()

	if !isValid {
		return fmt.Errorf("密码错误")
	}

	return nil
}

// 使用TOTP验证码解密私钥
func (wm *WalletManager) decryptPrivateKeyWithTOTP(totpCode string) (*solana.PrivateKey, error) {
	// 获取TOTP密钥
	walletBytes, err := os.ReadFile("wallet.json")
	if err != nil {
		return nil, err
	}

	var walletData map[string]interface{}
	json.Unmarshal(walletBytes, &walletData)
	totpSecret := walletData["totp_secret"].(string)

	fmt.Printf("解密时使用的TOTP密钥: %s\n", totpSecret)
	fmt.Printf("输入的验证码: %s\n", totpCode)

	// 验证TOTP验证码是否正确
	if !verifyTOTP(totpSecret, totpCode) {
		return nil, fmt.Errorf("TOTP验证失败")
	}

	// 使用TOTP密钥解密私钥
	salt, err := base64.StdEncoding.DecodeString(wm.wallet.Salt)
	if err != nil {
		return nil, fmt.Errorf("钱包数据损坏")
	}

	iv, err := base64.StdEncoding.DecodeString(wm.wallet.IV)
	if err != nil {
		return nil, fmt.Errorf("钱包数据损坏")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(wm.wallet.EncryptedPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("钱包数据损坏")
	}

	fmt.Printf("解密时使用的盐: %x\n", salt)
	fmt.Printf("解密时使用的IV: %x\n", iv)

	totpKey := generateAESKey(totpSecret, salt)
	fmt.Printf("解密时生成的TOTP密钥哈希: %x\n", totpKey)

	block, err := aes.NewCipher(totpKey)
	if err != nil {
		return nil, fmt.Errorf("解密失败")
	}

	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(plaintext, ciphertext)

	// 验证私钥长度
	if len(plaintext) != 64 {
		return nil, fmt.Errorf("TOTP验证失败")
	}

	// 安全地验证私钥
	var privateKey *solana.PrivateKey
	var isValid bool

	func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("私钥验证时发生panic: %v\n", r)
				isValid = false
			}
		}()

		pk := solana.PrivateKey(plaintext)
		publicKey := pk.PublicKey()
		fmt.Printf("解密出的公钥: %s\n", publicKey.String())
		fmt.Printf("期望的公钥: %s\n", wm.wallet.PublicKey)

		if publicKey.String() == wm.wallet.PublicKey {
			privateKey = &pk
			isValid = true
		} else {
			isValid = false
		}
	}()

	if !isValid {
		return nil, fmt.Errorf("TOTP验证失败")
	}

	return privateKey, nil
}

// 安全输入密码
func getPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}
	fmt.Println()
	return string(bytePassword), nil
}

// 生成TOTP密钥 - Base32格式
func generateTOTPSecret() string {
	secret := make([]byte, 20)
	rand.Read(secret)
	return base32.StdEncoding.EncodeToString(secret)
}

// 验证TOTP
func verifyTOTP(secret, code string) bool {
	fmt.Printf("验证TOTP - 密钥: %s, 验证码: %s\n", secret, code)
	isValid := totp.Validate(code, secret)
	fmt.Printf("TOTP验证结果: %v\n", isValid)
	return isValid
}

// 加密已知私钥
func encryptKnownPrivateKey() error {
	fmt.Println("=== 加密已知私钥 ===")

	// 获取私钥
	fmt.Print("请输入私钥: ")
	var privateKeyStr string
	fmt.Scanln(&privateKeyStr)

	// 解析私钥
	privateKey, err := solana.PrivateKeyFromBase58(privateKeyStr)
	if err != nil {
		return fmt.Errorf("无效的私钥格式: %v", err)
	}

	fmt.Printf("私钥对应的公钥: %s\n", privateKey.PublicKey().String())

	// 获取加密密码
	password, err := getPassword("请输入加密密码: ")
	if err != nil {
		return err
	}

	// 确认密码
	confirmPassword, err := getPassword("请确认密码: ")
	if err != nil {
		return err
	}

	if password != confirmPassword {
		return fmt.Errorf("密码不匹配")
	}

	// 生成TOTP密钥
	totpSecret := generateTOTPSecret()
	fmt.Printf("TOTP密钥 (请保存到Google Authenticator): %s\n", totpSecret)
	fmt.Println("请将上述TOTP密钥添加到Google Authenticator应用中")
	fmt.Println("然后输入Google Authenticator显示的6位验证码进行验证")

	// 验证TOTP是否正确绑定
	for {
		totpCode, err := getPassword("请输入Google Authenticator验证码: ")
		if err != nil {
			return err
		}

		if verifyTOTP(totpSecret, totpCode) {
			fmt.Println("✓ TOTP验证成功，Google Authenticator绑定正确")
			break
		} else {
			fmt.Println("✗ TOTP验证失败，请检查:")
			fmt.Println("  1. TOTP密钥是否正确添加到Google Authenticator")
			fmt.Println("  2. 验证码是否输入正确")
			fmt.Println("  3. 时间是否同步")

			retry, err := getPassword("是否重试? (y/n): ")
			if err != nil {
				return err
			}
			if retry != "y" && retry != "Y" {
				return fmt.Errorf("TOTP验证失败，加密取消")
			}
		}
	}

	// 使用验证过的TOTP密钥加密私钥
	encryptedWallet, err := encryptPrivateKeyWithTOTP(&privateKey, password, totpSecret)
	if err != nil {
		return err
	}

	// 保存加密钱包到文件
	walletData := map[string]interface{}{
		"wallet":      encryptedWallet,
		"totp_secret": totpSecret,
	}

	walletBytes, err := json.MarshalIndent(walletData, "", "  ")
	if err != nil {
		return err
	}

	err = os.WriteFile("wallet.json", walletBytes, 0600)
	if err != nil {
		return err
	}

	fmt.Println("私钥加密成功! 已保存到 wallet.json")
	fmt.Println("安全说明:")
	fmt.Println("- 即使有密码和wallet.json文件，没有Google验证码也无法解密私钥")
	fmt.Println("- 只有同时拥有正确密码和正确Google验证码才能获得私钥")
	return nil
}

// 加载现有钱包
func loadWallet() (*WalletManager, error) {
	walletBytes, err := os.ReadFile("wallet.json")
	if err != nil {
		return nil, err
	}

	var walletData map[string]interface{}
	err = json.Unmarshal(walletBytes, &walletData)
	if err != nil {
		return nil, err
	}

	walletJSON, err := json.Marshal(walletData["wallet"])
	if err != nil {
		return nil, err
	}

	var encryptedWallet EncryptedWallet
	err = json.Unmarshal(walletJSON, &encryptedWallet)
	if err != nil {
		return nil, err
	}

	return &WalletManager{
		client: rpc.New(rpc.DevNet_RPC),
		wallet: &encryptedWallet,
	}, nil
}

// 安全转账 - 双重验证
func (wm *WalletManager) secureTransfer(toAddress string, amount uint64) error {
	// 第一步：获取并验证密码
	password, err := getPassword("请输入钱包密码: ")
	if err != nil {
		return err
	}

	// 验证密码（不返回私钥）
	err = wm.verifyPassword(password)
	if err != nil {
		return fmt.Errorf("密码错误: %v", err)
	}

	fmt.Println("✓ 密码验证成功")

	// 第二步：获取TOTP验证码
	totpCode, err := getPassword("请输入Google Authenticator验证码: ")
	if err != nil {
		return err
	}

	// 使用TOTP验证码解密私钥
	privateKey, err := wm.decryptPrivateKeyWithTOTP(totpCode)
	if err != nil {
		return fmt.Errorf("TOTP验证失败: %v", err)
	}

	fmt.Println("✓ TOTP验证成功")

	// 执行转账
	txHash, err := wm.transferSOL(privateKey, toAddress, amount)
	if err != nil {
		return fmt.Errorf("转账失败: %v", err)
	}

	fmt.Printf("✓ 转账成功! 交易哈希: %s\n", txHash)
	return nil
}

// 转账SOL
func (wm *WalletManager) transferSOL(fromPrivateKey *solana.PrivateKey, toAddress string, amount uint64) (string, error) {
	toPubKey, err := solana.PublicKeyFromBase58(toAddress)
	if err != nil {
		return "", fmt.Errorf("无效的接收地址: %v", err)
	}

	fromPubKey := fromPrivateKey.PublicKey()

	instruction := system.NewTransferInstruction(
		amount,
		fromPubKey,
		toPubKey,
	).Build()

	recent, err := wm.client.GetLatestBlockhash(context.Background(), rpc.CommitmentFinalized)
	if err != nil {
		return "", fmt.Errorf("获取区块哈希失败: %v", err)
	}

	tx, err := solana.NewTransaction(
		[]solana.Instruction{instruction},
		recent.Value.Blockhash,
		solana.TransactionPayer(fromPubKey),
	)
	if err != nil {
		return "", fmt.Errorf("创建交易失败: %v", err)
	}

	_, err = tx.Sign(
		func(key solana.PublicKey) *solana.PrivateKey {
			if key.String() == fromPubKey.String() {
				return fromPrivateKey
			}
			return nil
		},
	)
	if err != nil {
		return "", fmt.Errorf("签名交易失败: %v", err)
	}

	sig, err := wm.client.SendTransaction(context.Background(), tx)
	if err != nil {
		return "", fmt.Errorf("发送交易失败: %v", err)
	}

	return sig.String(), nil
}

// 自定加密交易的方式
func transfer() {
	if len(os.Args) < 2 {
		fmt.Println("=== Solana 安全钱包 ===")
		fmt.Println("使用方法:")
		fmt.Println("  1. go run main.go 1                    # 加密已知私钥")
		fmt.Println("  2. go run main.go 2 <接收地址> <金额>   # 安全转账")
		fmt.Println("  3. go run main.go 3                    # 查看钱包信息")
		fmt.Println("  4. go run main.go 4                    # 创建新钱包")
		fmt.Println("\n示例:")
		fmt.Println("  go run main.go 1")
		fmt.Println("  go run main.go 2 11111111111111111111111111111111 1000000")
		fmt.Println("  go run main.go 4")
		os.Exit(1)
	}

	mode, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Printf("错误: 无效的模式 %v\n", err)
		os.Exit(1)
	}

	switch mode {
	case 1:
		// 模式1：加密已知私钥
		err = encryptKnownPrivateKey()
		if err != nil {
			log.Fatalf("加密私钥失败: %v", err)
		}

	case 2:
		// 模式2：安全转账
		if len(os.Args) != 4 {
			fmt.Println("错误: 转账需要指定接收地址和金额")
			fmt.Println("用法: go run main.go 2 <接收地址> <金额>")
			fmt.Println("金额格式: 支持 SOL (如 0.001) 或 lamports (如 1000000)")
			os.Exit(1)
		}

		toAddress := os.Args[2]
		amountStr := os.Args[3]

		// 解析金额，支持 SOL 和 lamports
		var amount uint64
		if strings.Contains(amountStr, ".") {
			// 如果是小数，按 SOL 处理
			solAmount, err := strconv.ParseFloat(amountStr, 64)
			if err != nil {
				fmt.Printf("错误: 无效的金额格式 %v\n", err)
				os.Exit(1)
			}
			amount = uint64(solAmount * 1e9) // 转换为 lamports
		} else {
			// 如果是整数，按 lamports 处理
			var err error
			amount, err = strconv.ParseUint(amountStr, 10, 64)
			if err != nil {
				fmt.Printf("错误: 无效的金额 %v\n", err)
				os.Exit(1)
			}
		}

		// 检查钱包文件是否存在
		if _, err := os.Stat("wallet.json"); os.IsNotExist(err) {
			fmt.Println("错误: 钱包文件不存在，请先运行 'go run main.go 1' 加密私钥")
			os.Exit(1)
		}

		// 加载钱包
		wm, err := loadWallet()
		if err != nil {
			log.Fatalf("加载钱包失败: %v", err)
		}

		fmt.Printf("钱包公钥: %s\n", wm.wallet.PublicKey)
		fmt.Printf("转账金额: %d lamports (%.9f SOL)\n", amount, float64(amount)/1e9)

		// 执行转账
		err = wm.secureTransfer(toAddress, amount)
		if err != nil {
			log.Fatalf("转账失败: %v", err)
		}

	case 3:
		// 模式3：查看钱包信息
		if _, err := os.Stat("wallet.json"); os.IsNotExist(err) {
			fmt.Println("钱包文件不存在")
			os.Exit(1)
		}

		wm, err := loadWallet()
		if err != nil {
			log.Fatalf("加载钱包失败: %v", err)
		}

		fmt.Printf("钱包公钥: %s\n", wm.wallet.PublicKey)
		fmt.Println("钱包已加密，需要密码和TOTP验证码才能访问")

	case 4:
		// 模式4：创建新钱包
		err = createNewWallet()
		if err != nil {
			log.Fatalf("创建钱包失败: %v", err)
		}

	default:
		fmt.Println("错误: 无效的模式，请使用 1、2、3 或 4")
		os.Exit(1)
	}
}

// 创建新钱包
func createNewWallet() error {
	fmt.Println("=== 创建新钱包 ===")

	// 创建Solana钱包
	solanaPrivateKey := solana.NewWallet().PrivateKey

	fmt.Printf("新钱包创建成功!\n")
	fmt.Printf("私钥: %s\n", solanaPrivateKey.String())
	fmt.Printf("公钥: %s\n", solanaPrivateKey.PublicKey().String())
	fmt.Printf("地址: %s\n", solanaPrivateKey.PublicKey().String())

	// 询问是否要加密保存
	fmt.Print("\n是否要加密保存这个钱包? (y/n): ")
	var choice string
	fmt.Scanln(&choice)

	if choice == "y" || choice == "Y" {
		// 获取加密密码
		password, err := getPassword("请输入加密密码: ")
		if err != nil {
			return err
		}

		// 确认密码
		confirmPassword, err := getPassword("请确认密码: ")
		if err != nil {
			return err
		}

		if password != confirmPassword {
			return fmt.Errorf("密码不匹配")
		}

		// 生成TOTP密钥
		totpSecret := generateTOTPSecret()
		fmt.Printf("TOTP密钥 (请保存到Google Authenticator): %s\n", totpSecret)
		fmt.Println("请将上述TOTP密钥添加到Google Authenticator应用中")

		// 验证TOTP是否正确绑定
		for {
			totpCode, err := getPassword("请输入Google Authenticator验证码: ")
			if err != nil {
				return err
			}

			if verifyTOTP(totpSecret, totpCode) {
				fmt.Println("✓ TOTP验证成功，Google Authenticator绑定正确")
				break
			} else {
				fmt.Println("✗ TOTP验证失败，请重试")
			}
		}

		// 加密私钥
		encryptedWallet, err := encryptPrivateKeyWithTOTP(&solanaPrivateKey, password, totpSecret)
		if err != nil {
			return err
		}

		// 保存加密钱包到文件
		walletData := map[string]interface{}{
			"wallet":      encryptedWallet,
			"totp_secret": totpSecret,
		}

		walletBytes, err := json.MarshalIndent(walletData, "", "  ")
		if err != nil {
			return err
		}

		err = os.WriteFile("wallet.json", walletBytes, 0600)
		if err != nil {
			return err
		}

		fmt.Println("钱包加密成功! 已保存到 wallet.json")
	}

	return nil
}

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/go-redis/redis/v8"
)

const (
	rpcEndpoint = "https://api.devnet.solana.com"
	// 监听间隔时间（秒）
	monitorInterval = 2
	// 最大重试次数
	maxRetries = 3
	// 重试间隔（秒）
	retryInterval = 5
	// 配置文件路径
	configFile = "addresses.json"
)

// 交易类型配置
type TxTypeConfig struct {
	ShowSOLTransfer     bool
	ShowTokenTransfer   bool
	ShowVoteTransfer    bool
	ShowStakeTransfer   bool
	ShowComputeTransfer bool
	ShowOtherTransfer   bool
}

// 监控地址配置结构
type AddressConfig struct {
	MonitorAddresses []string `json:"monitor_addresses"`
	Description      string   `json:"description"`
	CreatedAt        string   `json:"created_at"`
}

// 监控地址配置
type MonitorConfig struct {
	Addresses map[string]bool // 要监控的地址列表
	TxConfig  TxTypeConfig    // 交易类型配置
}

// 监控转账信息结构
type MonitorTransfer struct {
	MonitorAddress string  `json:"monitor_address"`
	FromAddress    string  `json:"from_address"`
	Amount         float64 `json:"amount"`
	TxHash         string  `json:"tx_hash"`
	TxTime         string  `json:"tx_time"`
	Status         string  `json:"status"`
	Fee            float64 `json:"fee"`
}

// 默认配置：只显示SOL转账
func getDefaultConfig() TxTypeConfig {
	return TxTypeConfig{
		ShowSOLTransfer:     true,
		ShowTokenTransfer:   false,
		ShowVoteTransfer:    false,
		ShowStakeTransfer:   false,
		ShowComputeTransfer: false,
		ShowOtherTransfer:   false,
	}
}

// 从JSON文件读取监控地址
func loadAddressesFromFile(filename string) (map[string]bool, error) {
	addresses := make(map[string]bool)

	// 检查文件是否存在
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return addresses, fmt.Errorf("配置文件 %s 不存在", filename)
	}

	// 读取文件内容
	data, err := os.ReadFile(filename)
	if err != nil {
		return addresses, fmt.Errorf("读取配置文件失败: %v", err)
	}

	// 解析JSON
	var config AddressConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return addresses, fmt.Errorf("解析JSON配置失败: %v", err)
	}

	// 转换地址列表为map
	for _, addr := range config.MonitorAddresses {
		addr = strings.TrimSpace(addr)
		if addr != "" {
			addresses[addr] = true
		}
	}

	return addresses, nil
}

// 创建默认配置文件
func createDefaultConfigFile(filename string) error {
	defaultConfig := AddressConfig{
		MonitorAddresses: []string{
			"11111111111111111111111111111111", // 示例地址1
			"22222222222222222222222222222222", // 示例地址2
			"33333333333333333333333333333333", // 示例地址3
		},
		Description: "监控地址列表 - 请修改为您要监控的地址",
		CreatedAt:   time.Now().Format("2006-01-02T15:04:05Z"),
	}

	data, err := json.MarshalIndent(defaultConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("生成默认配置失败: %v", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("写入配置文件失败: %v", err)
	}

	return nil
}

// 获取监控配置
func getMonitorConfig() MonitorConfig {
	txConfig := getDefaultConfig()

	// 从环境变量读取交易类型配置
	if os.Getenv("SHOW_TOKEN_TRANSFER") == "true" {
		txConfig.ShowTokenTransfer = true
	}
	if os.Getenv("SHOW_VOTE_TRANSFER") == "true" {
		txConfig.ShowVoteTransfer = true
	}
	if os.Getenv("SHOW_STAKE_TRANSFER") == "true" {
		txConfig.ShowStakeTransfer = true
	}
	if os.Getenv("SHOW_COMPUTE_TRANSFER") == "true" {
		txConfig.ShowComputeTransfer = true
	}
	if os.Getenv("SHOW_OTHER_TRANSFER") == "true" {
		txConfig.ShowOtherTransfer = true
	}

	// 从JSON文件读取监控地址
	addresses, err := loadAddressesFromFile(configFile)
	if err != nil {
		fmt.Printf("****** 警告: %v ******\n", err)
		fmt.Printf("****** 尝试创建默认配置文件 %s ******\n", configFile)

		if createErr := createDefaultConfigFile(configFile); createErr != nil {
			fmt.Printf("****** 创建默认配置文件失败: %v ******\n", createErr)
			fmt.Printf("****** 请手动创建 %s 文件并添加监控地址 ******\n", configFile)
			os.Exit(1)
		}

		fmt.Printf("****** 已创建默认配置文件 %s，请编辑后重新运行程序 ******\n", configFile)
		os.Exit(1)
	}

	// 检查是否有监控地址
	if len(addresses) == 0 {
		fmt.Printf("****** 错误: 配置文件 %s 中没有找到有效的监控地址 ******\n", configFile)
		fmt.Printf("****** 请检查配置文件格式是否正确 ******\n")
		os.Exit(1)
	}

	return MonitorConfig{
		Addresses: addresses,
		TxConfig:  txConfig,
	}
}

// 获取最新区块号
func getLatestSlot(client *rpc.Client) (uint64, error) {
	ctx := context.Background()
	slot, err := client.GetSlot(ctx, rpc.CommitmentFinalized)
	if err != nil {
		return 0, fmt.Errorf("failed to get latest slot: %v", err)
	}
	return slot, nil
}

// 辅助函数
func shortenAddress(addr string) string {
	if len(addr) > 8 {
		return addr[:4] + "..." + addr[len(addr)-4:]
	}
	return addr
}

func isSystemAccount(addr string) bool {
	systemAccounts := map[string]bool{
		"11111111111111111111111111111111":            true, // System Program
		"Vote111111111111111111111111111111111111111": true, // Vote Program
		"Stake11111111111111111111111111111111111111": true, // Stake Program
		"ComputeBudget111111111111111111111111111111": true, // Compute Budget Program
		"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA": true, // Token Program
	}
	return systemAccounts[addr]
}

func getTxType(logs []string) string {
	programCalls := make(map[string]bool)

	for _, log := range logs {
		if strings.Contains(log, "Program") && strings.Contains(log, "invoke") {
			parts := strings.Split(log, " ")
			if len(parts) >= 2 {
				programCalls[parts[1]] = true
			}
		}
	}

	if programCalls["11111111111111111111111111111111"] {
		return "SOL转账"
	} else if programCalls["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"] {
		return "Token转账"
	} else if programCalls["Vote111111111111111111111111111111111111111"] {
		return "投票交易"
	} else if programCalls["Stake11111111111111111111111111111111111111"] {
		return "质押交易"
	} else if programCalls["ComputeBudget111111111111111111111111111111"] {
		return "计算预算交易"
	} else {
		var programs []string
		for program := range programCalls {
			if !isSystemAccount(program) {
				programs = append(programs, shortenAddress(program))
			}
		}
		if len(programs) > 0 {
			return fmt.Sprintf("程序调用: %s", strings.Join(programs, ", "))
		}
		return "其他交易"
	}
}

// 检查是否应该显示该交易类型
func shouldShowTransaction(txType string, config TxTypeConfig) bool {
	switch txType {
	case "SOL转账":
		return config.ShowSOLTransfer
	case "Token转账":
		return config.ShowTokenTransfer
	case "投票交易":
		return config.ShowVoteTransfer
	case "质押交易":
		return config.ShowStakeTransfer
	case "计算预算交易":
		return config.ShowComputeTransfer
	default:
		return config.ShowOtherTransfer
	}
}

// 检查地址是否在监控列表中
func isMonitoredAddress(addr string, monitorAddrs map[string]bool) bool {
	return monitorAddrs[addr]
}

func processTransaction(txIndex int, tx rpc.TransactionWithMeta, config MonitorConfig, blockTime int64) {
	decoded, err := tx.GetTransaction()
	if err != nil {
		return
	}

	txType := getTxType(tx.Meta.LogMessages)
	if !shouldShowTransaction(txType, config.TxConfig) {
		return
	}

	txHash := ""
	if len(decoded.Signatures) > 0 {
		txHash = decoded.Signatures[0].String()
	}

	var txTime string
	if blockTime > 0 {
		txTime = time.Unix(blockTime, 0).Format("2006-01-02 15:04:05")
	} else {
		txTime = "未知"
	}

	status := "成功"
	if tx.Meta.Err != nil {
		status = "失败"
	}

	fee := float64(tx.Meta.Fee) / 1e9

	balanceChanges := make(map[string]int64)
	for i, key := range decoded.Message.AccountKeys {
		if i < len(tx.Meta.PreBalances) && i < len(tx.Meta.PostBalances) {
			preBalance := tx.Meta.PreBalances[i]
			postBalance := tx.Meta.PostBalances[i]
			if preBalance != postBalance {
				change := int64(postBalance) - int64(preBalance)
				balanceChanges[key.String()] = change
			}
		}
	}

	var fromAddr string
	for addr, change := range balanceChanges {
		if change < 0 && !isSystemAccount(addr) && !isMonitoredAddress(addr, config.Addresses) {
			fromAddr = addr
			break
		}
	}

	if txType == "SOL转账" {
		for addr, change := range balanceChanges {
			if change > 0 && !isSystemAccount(addr) && isMonitoredAddress(addr, config.Addresses) {
				transfer := MonitorTransfer{
					MonitorAddress: addr,
					FromAddress:    fromAddr,
					Amount:         float64(change) / 1e9,
					TxHash:         txHash,
					TxTime:         txTime,
					Status:         status,
					Fee:            fee,
				}

				// 打印详细信息
				fmt.Printf("****** 监控地址: %s ******\n", transfer.MonitorAddress)
				fmt.Printf("****** 转出地址: %s ******\n", transfer.FromAddress)
				fmt.Printf("****** 收到金额: %.9f SOL ******\n", transfer.Amount)
				fmt.Printf("****** 交易哈希: %s ******\n", transfer.TxHash)
				fmt.Printf("****** 交易时间: %s ******\n", transfer.TxTime)
				fmt.Printf("****** 交易状态: %s ******\n", transfer.Status)
				fmt.Printf("****** 手续费: %.9f SOL ******\n", transfer.Fee)
				fmt.Println("****** ================== ******")

				// 保存到redis
				ctx := context.Background()
				if err := saveToRedis(ctx, "solana:monitor:transfers", transfer); err != nil {
					fmt.Printf("****** 保存到redis失败: %v ******\n", err)
				}
			}
		}
	}
}

func getBlockDetails(client *rpc.Client, slot uint64) (*rpc.GetBlockResult, error) {
	ctx := context.Background()

	// 设置最大支持的交易版本为0
	maxVersion := uint64(0)

	opts := rpc.GetBlockOpts{
		Encoding:                       solana.EncodingBase64,
		TransactionDetails:             "full",
		Commitment:                     rpc.CommitmentFinalized,
		MaxSupportedTransactionVersion: &maxVersion,
	}

	block, err := client.GetBlockWithOpts(ctx, slot, &opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get block %d: %v", slot, err)
	}

	return block, nil
}

// 注释掉区块信息打印
/*
func printBlockInfo(block *rpc.GetBlockResult, blockNum uint64) {
	fmt.Printf("****** 区块 %d 详细信息 ******\n", blockNum)
	if block.BlockTime != nil {
		fmt.Printf("****** 区块时间: %v ******\n", time.Unix(int64(*block.BlockTime), 0))
	}
	fmt.Printf("****** 区块高度: %d ******\n", block.BlockHeight)
	fmt.Printf("****** 父区块: %d ******\n", block.ParentSlot)
	fmt.Printf("****** 交易数量: %d ******\n", len(block.Transactions))
	fmt.Println("****** ================== ******\n")
}
*/

// 处理单个区块
func processBlock(client *rpc.Client, blockNum uint64, config MonitorConfig) error {
	// 带重试的区块获取
	var block *rpc.GetBlockResult
	var err error

	for retry := 0; retry < maxRetries; retry++ {
		block, err = getBlockDetails(client, blockNum)
		if err == nil {
			break
		}

		if retry < maxRetries-1 {
			// 注释掉重试信息
			// fmt.Printf("****** 获取区块 %d 失败，%d 秒后重试... (错误: %v) ******\n", blockNum, retryInterval, err)
			time.Sleep(time.Duration(retryInterval) * time.Second)
		}
	}

	if err != nil {
		return fmt.Errorf("获取区块 %d 失败，已重试 %d 次: %v", blockNum, maxRetries, err)
	}

	// 注释掉区块信息打印
	// printBlockInfo(block, blockNum)

	// 处理区块中的交易
	validTxCount := 0
	var blockTime int64
	if block.BlockTime != nil {
		blockTime = int64(*block.BlockTime)
	} else {
		blockTime = 0
	}
	for i, tx := range block.Transactions {
		// 保存当前交易数量
		prevCount := validTxCount
		processTransaction(i+1, tx, config, blockTime)
		// 如果交易被处理了（没有被过滤），增加计数
		if validTxCount == prevCount {
			validTxCount++
		}
	}

	// 注释掉无交易提示
	/*
		if validTxCount == 0 {
			fmt.Printf("****** 区块 %d 中没有符合条件的交易 ******\n", blockNum)
		}
	*/

	return nil
}

// 循环监听区块
func monitorBlocks(client *rpc.Client, startBlock uint64, config MonitorConfig) {
	currentBlock := startBlock

	// 只保留启动信息
	fmt.Printf("****** 开始监听区块，起始区块: %d ******\n", startBlock)
	fmt.Printf("****** 监听间隔: %d 秒 ******\n", monitorInterval)
	fmt.Printf("****** 配置文件: %s ******\n", configFile)
	fmt.Printf("****** 监控地址数量: %d ******\n", len(config.Addresses))
	fmt.Println("****** 监控地址列表: ******")
	for addr := range config.Addresses {
		fmt.Printf("******   %s ******\n", addr)
	}
	fmt.Println("****** 按 Ctrl+C 停止监听 ******\n")

	for {
		// 获取最新区块号
		latestSlot, err := getLatestSlot(client)
		if err != nil {
			// 注释掉错误信息
			// fmt.Printf("****** 获取最新区块号失败: %v ******\n", err)
			time.Sleep(time.Duration(monitorInterval) * time.Second)
			continue
		}

		// 检查当前区块是否超过最新区块
		if currentBlock > latestSlot {
			// 注释掉等待信息
			// fmt.Printf("****** 当前区块 %d 超过最新区块 %d，等待新区块... ******\n", currentBlock, latestSlot)
			time.Sleep(time.Duration(monitorInterval) * time.Second)
			continue
		}

		// 打印当前区块高度
		fmt.Printf("****** 当前区块高度: %d (最新区块: %d) ******\n", currentBlock, latestSlot)

		// 处理当前区块
		// 注释掉处理信息
		// fmt.Printf("\n****** 正在处理区块 %d (最新区块: %d) ******\n", currentBlock, latestSlot)
		err = processBlock(client, currentBlock, config)
		if err != nil {
			// 注释掉错误信息
			// fmt.Printf("****** 处理区块 %d 失败: %v ******\n", currentBlock, err)
			// 如果处理失败，等待一段时间后继续下一个区块
			time.Sleep(time.Duration(monitorInterval) * time.Second)
		}

		// 移动到下一个区块
		currentBlock++

		// 等待指定间隔
		time.Sleep(time.Duration(monitorInterval) * time.Second)
	}
}

var redisClient *redis.Client

func initRedis() {
	redisClient = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // 替换为你的Redis密码
		DB:       3,  // 替换为你的Redis DB
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := redisClient.Ping(ctx).Result()
	if err != nil {
		fmt.Printf("****** Redis连接失败: %v ******\n", err)
		os.Exit(1)
	} else {
		fmt.Println("****** Redis连接成功 ******")
	}
}

func saveToRedis(ctx context.Context, key string, data MonitorTransfer) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return redisClient.LPush(ctx, key, b).Err()
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("****** Usage: go run main.go <start_block_number> ******")
		fmt.Println("\n****** 环境变量配置: ******")
		fmt.Println("******   SHOW_TOKEN_TRANSFER=true    # 显示Token转账 ******")
		fmt.Println("******   SHOW_VOTE_TRANSFER=true     # 显示投票交易 ******")
		fmt.Println("******   SHOW_STAKE_TRANSFER=true    # 显示质押交易 ******")
		fmt.Println("******   SHOW_COMPUTE_TRANSFER=true  # 显示计算预算交易 ******")
		fmt.Println("******   SHOW_OTHER_TRANSFER=true    # 显示其他交易 ******")
		fmt.Println("\n****** 配置文件: addresses.json ******")
		fmt.Println("****** 程序会从指定区块开始，自动循环监听后续区块 ******")
		os.Exit(1)
	}

	startBlock, err := strconv.ParseUint(os.Args[1], 10, 64)
	if err != nil {
		fmt.Printf("****** Error parsing block number: %v ******\n", err)
		os.Exit(1)
	}

	// 获取监控配置
	config := getMonitorConfig()

	client := rpc.New(rpcEndpoint)

	// 验证起始区块是否有效
	latestSlot, err := getLatestSlot(client)
	if err != nil {
		fmt.Printf("****** Error getting latest slot: %v ******\n", err)
		os.Exit(1)
	}

	if startBlock > latestSlot {
		fmt.Printf("****** 起始区块 %d 超过最新区块 %d，请使用有效的区块号 ******\n", startBlock, latestSlot)
		os.Exit(1)
	}

	initRedis()

	// 开始循环监听
	monitorBlocks(client, startBlock, config)
}

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/go-redis/redis/v8"
)

const (
	rpcEndpoint = "https://api.devnet.solana.com"
	// 监听间隔时间（毫秒）- 改为更快的间隔
	monitorInterval = 200 // 200毫秒 = 0.2秒
	// 快速追赶时的间隔（毫秒）
	fastInterval = 50 // 50毫秒
	// 超快速追赶间隔（毫秒）
	ultraFastInterval = 10 // 10毫秒
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

// 并行处理区块
func processBlockParallel(client *rpc.Client, blockNum uint64, config MonitorConfig) error {
	// 获取区块
	block, err := getBlockDetails(client, blockNum)
	if err != nil {
		return err
	}

	// 如果区块没有交易，直接跳过
	if len(block.Transactions) == 0 {
		return nil
	}

	// 使用协程并行处理交易
	var wg sync.WaitGroup
	for i, tx := range block.Transactions {
		wg.Add(1)
		go func(index int, transaction rpc.TransactionWithMeta) {
			defer wg.Done()
			processTransaction(index+1, transaction, config, int64(*block.BlockTime))
		}(i, tx)
	}
	wg.Wait()

	return nil
}

// 循环监听区块
func monitorBlocks(client *rpc.Client, startBlock uint64, config MonitorConfig) {
	currentBlock := startBlock

	// 只保留启动信息
	fmt.Printf("****** 开始监听区块，起始区块: %d ******\n", startBlock)
	fmt.Printf("****** 监听间隔: %d 毫秒 ******\n", monitorInterval)
	fmt.Printf("****** 快速追赶间隔: %d 毫秒 ******\n", fastInterval)
	fmt.Printf("****** 超快速追赶间隔: %d 毫秒 ******\n", ultraFastInterval)
	fmt.Printf("****** 配置文件: %s ******\n", configFile)
	fmt.Printf("****** 监控地址数量: %d ******\n", len(config.Addresses))
	fmt.Println("****** 监控地址列表: ******")
	for addr := range config.Addresses {
		fmt.Printf("******   %s ******\n", addr)
	}
	fmt.Println("****** 按 Ctrl+C 停止监听 ******\n")

	// 用于同步的互斥锁
	var mu sync.Mutex
	var isChasing bool = false

	for {
		// 获取最新区块号
		latestSlot, err := getLatestSlot(client)
		if err != nil {
			fmt.Printf("****** 获取最新区块号失败: %v ******\n", err)
			time.Sleep(time.Duration(monitorInterval) * time.Millisecond)
			continue
		}

		// 检查是否需要快速追赶
		if latestSlot-currentBlock > 3 {
			mu.Lock()
			if !isChasing {
				isChasing = true
				mu.Unlock()

				fmt.Printf("****** 当前区块 %d 落后最新区块 %d 共 %d 个区块，启动快速追赶协程 ******\n",
					currentBlock, latestSlot, latestSlot-currentBlock)

				// 启动协程进行快速追赶
				go func(startBlock, targetBlock uint64) {
					fmt.Printf("****** 快速追赶协程开始: 从区块 %d 追赶至 %d ******\n", startBlock, targetBlock)

					for blockNum := startBlock; blockNum < targetBlock; blockNum++ {
						fmt.Printf("****** 快速追赶: 处理区块 %d ******\n", blockNum)
						err := processBlockParallel(client, blockNum, config)
						if err != nil {
							fmt.Printf("****** 快速追赶处理区块 %d 失败: %v ******\n", blockNum, err)
						}
						time.Sleep(time.Duration(fastInterval) * time.Millisecond)
					}

					fmt.Printf("****** 快速追赶协程完成: 已处理区块 %d 到 %d ******\n", startBlock, targetBlock-1)

					mu.Lock()
					isChasing = false
					mu.Unlock()
				}(currentBlock, latestSlot)

				// 正常监听模式直接跳到最新区块
				fmt.Printf("****** 正常监听模式跳转到最新区块: %d ******\n", latestSlot)
				currentBlock = latestSlot
			} else {
				mu.Unlock()
				// 如果已经在追赶中，正常监听模式也跳到最新区块
				fmt.Printf("****** 追赶进行中，正常监听模式跳转到最新区块: %d ******\n", latestSlot)
				currentBlock = latestSlot
			}
		}

		// 如果当前区块超过最新区块，等待新区块
		if currentBlock > latestSlot {
			fmt.Printf("****** 当前区块 %d 超过最新区块 %d，等待新区块... ******\n", currentBlock, latestSlot)
			time.Sleep(time.Duration(monitorInterval) * time.Millisecond)
			continue
		}

		// 处理当前区块
		fmt.Printf("****** 正常监听: 处理区块 %d (最新区块: %d) ******\n", currentBlock, latestSlot)

		err = processBlockParallel(client, currentBlock, config)
		if err != nil {
			fmt.Printf("****** 处理区块 %d 失败: %v ******\n", currentBlock, err)
			time.Sleep(time.Duration(monitorInterval) * time.Millisecond)
		}

		// 移动到下一个区块
		currentBlock++

		// 等待指定间隔
		time.Sleep(time.Duration(monitorInterval) * time.Millisecond)
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
	if len(os.Args) < 2 {
		fmt.Println("****** Usage: ******")
		fmt.Println("******   go run main.go 0                    # 从最新区块开始监听 ******")
		fmt.Println("******   go run main.go 1 <block_number>     # 从指定区块开始监听 ******")
		fmt.Println("******   go run main.go 2 <start_block> <end_block>  # 监听指定区块范围 ******")
		fmt.Println("\n****** 环境变量配置: ******")
		fmt.Println("******   SHOW_TOKEN_TRANSFER=true    # 显示Token转账 ******")
		fmt.Println("******   SHOW_VOTE_TRANSFER=true     # 显示投票交易 ******")
		fmt.Println("******   SHOW_STAKE_TRANSFER=true    # 显示质押交易 ******")
		fmt.Println("******   SHOW_COMPUTE_TRANSFER=true  # 显示计算预算交易 ******")
		fmt.Println("******   SHOW_OTHER_TRANSFER=true    # 显示其他交易 ******")
		fmt.Println("\n****** 配置文件: addresses.json ******")
		os.Exit(1)
	}

	mode, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Printf("****** Error parsing mode: %v ******\n", err)
		os.Exit(1)
	}

	// 获取监控配置
	config := getMonitorConfig()
	initRedis()
	client := rpc.New(rpcEndpoint)

	switch mode {
	case 0:
		// 模式0：从最新区块开始监听
		latestSlot, err := getLatestSlot(client)
		if err != nil {
			fmt.Printf("****** Error getting latest slot: %v ******\n", err)
			os.Exit(1)
		}
		fmt.Printf("****** 模式0: 从最新区块 %d 开始监听 ******\n", latestSlot)
		monitorBlocks(client, latestSlot, config)

	case 1:
		// 模式1：从指定区块开始监听
		if len(os.Args) != 3 {
			fmt.Println("****** 模式1需要指定区块号: go run main.go 1 <block_number> ******")
			os.Exit(1)
		}

		startBlock, err := strconv.ParseUint(os.Args[2], 10, 64)
		if err != nil {
			fmt.Printf("****** Error parsing block number: %v ******\n", err)
			os.Exit(1)
		}

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

		fmt.Printf("****** 模式1: 从指定区块 %d 开始监听 ******\n", startBlock)
		monitorBlocks(client, startBlock, config)

	case 2:
		// 模式2：监听指定区块范围
		if len(os.Args) != 4 {
			fmt.Println("****** 模式2需要指定区块范围: go run main.go 2 <start_block> <end_block> ******")
			os.Exit(1)
		}

		startBlock, err := strconv.ParseUint(os.Args[2], 10, 64)
		if err != nil {
			fmt.Printf("****** Error parsing start block: %v ******\n", err)
			os.Exit(1)
		}

		endBlock, err := strconv.ParseUint(os.Args[3], 10, 64)
		if err != nil {
			fmt.Printf("****** Error parsing end block: %v ******\n", err)
			os.Exit(1)
		}

		if startBlock >= endBlock {
			fmt.Println("****** 起始区块必须小于结束区块 ******")
			os.Exit(1)
		}

		// 验证区块范围是否有效
		latestSlot, err := getLatestSlot(client)
		if err != nil {
			fmt.Printf("****** Error getting latest slot: %v ******\n", err)
			os.Exit(1)
		}

		if endBlock > latestSlot {
			fmt.Printf("****** 结束区块 %d 超过最新区块 %d，请使用有效的区块范围 ******\n", endBlock, latestSlot)
			os.Exit(1)
		}

		fmt.Printf("****** 模式2: 监听区块范围 %d 到 %d ******\n", startBlock, endBlock)
		monitorBlockRange(client, startBlock, endBlock, config)

	default:
		fmt.Println("****** 无效的模式，请使用 0、1 或 2 ******")
		os.Exit(1)
	}
}

// 新增：监听指定区块范围的函数
func monitorBlockRange(client *rpc.Client, startBlock, endBlock uint64, config MonitorConfig) {
	fmt.Printf("****** 开始监听区块范围: %d 到 %d ******\n", startBlock, endBlock)
	fmt.Printf("****** 监听间隔: %d 毫秒 ******\n", monitorInterval)
	fmt.Printf("****** 配置文件: %s ******\n", configFile)
	fmt.Printf("****** 监控地址数量: %d ******\n", len(config.Addresses))
	fmt.Println("****** 监控地址列表: ******")
	for addr := range config.Addresses {
		fmt.Printf("******   %s ******\n", addr)
	}
	fmt.Println("****** 按 Ctrl+C 停止监听 ******\n")

	for currentBlock := startBlock; currentBlock <= endBlock; currentBlock++ {
		fmt.Printf("****** 处理区块: %d / %d ******\n", currentBlock, endBlock)

		err := processBlock(client, currentBlock, config)
		if err != nil {
			fmt.Printf("****** 处理区块 %d 失败: %v ******\n", currentBlock, err)
		}

		// 等待指定间隔
		time.Sleep(time.Duration(monitorInterval) * time.Millisecond)
	}

	fmt.Printf("****** 区块范围监听完成: %d 到 %d ******\n", startBlock, endBlock)
}

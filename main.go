package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
)

const (
	rpcEndpoint = "https://api.devnet.solana.com"
	// 监听间隔时间（秒）
	monitorInterval = 2
	// 最大重试次数
	maxRetries = 3
	// 重试间隔（秒）
	retryInterval = 5
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

// 监控地址配置
type MonitorConfig struct {
	Addresses map[string]bool // 要监控的地址列表
	TxConfig  TxTypeConfig    // 交易类型配置
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

	// 初始化监控地址map
	addresses := make(map[string]bool)

	// 从环境变量读取监控地址（用逗号分隔）
	monitorAddrs := os.Getenv("MONITOR_ADDRESSES")
	if monitorAddrs != "" {
		addrList := strings.Split(monitorAddrs, ",")
		for _, addr := range addrList {
			addr = strings.TrimSpace(addr)
			if addr != "" {
				addresses[addr] = true
			}
		}
	}

	// 如果没有从环境变量读取到地址，使用默认地址列表
	if len(addresses) == 0 {
		defaultAddresses := []string{
			"5xSth6eYNeykmFXzCFL42dmD8jngqJUyBRaZbjz7Db5F", // 示例地址1
			"CTe3cr6nh4NJXESkCPvxodVGpgb52T2E24bdnvgzwRCX", // 示例地址2
			"Gu1jCbrMok1oEXwNEMNDoJrx136jhe15VGbzdAijazfJ", // 示例地址2
			// 可以在这里添加更多默认地址
		}
		for _, addr := range defaultAddresses {
			addresses[addr] = true
		}
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

func processTransaction(txIndex int, tx rpc.TransactionWithMeta, config MonitorConfig) {
	decoded, err := tx.GetTransaction()
	if err != nil {
		return
	}

	// 确定交易类型
	txType := getTxType(tx.Meta.LogMessages)

	// 检查是否应该显示该交易类型
	if !shouldShowTransaction(txType, config.TxConfig) {
		return
	}

	// 获取交易签名（哈希）
	txHash := "未知"
	if len(decoded.Signatures) > 0 {
		txHash = decoded.Signatures[0].String()
	}

	fmt.Printf("--- 交易 #%d ---\n", txIndex)
	fmt.Printf("交易哈希: %s\n", txHash)
	fmt.Printf("交易类型: %s\n", txType)

	// 显示交易状态和手续费
	if tx.Meta.Err == nil {
		fmt.Println("状态: 成功")
	} else {
		fmt.Printf("状态: 失败 (%s)\n", tx.Meta.Err)
	}
	fmt.Printf("手续费: %d lamports (%.9f SOL)\n", tx.Meta.Fee, float64(tx.Meta.Fee)/1e9)
	fmt.Println()

	// 显示账户余额变化
	fmt.Println("账户余额信息:")
	balanceChanges := make(map[string]int64)
	for i, key := range decoded.Message.AccountKeys {
		if i < len(tx.Meta.PreBalances) && i < len(tx.Meta.PostBalances) {
			preBalance := tx.Meta.PreBalances[i]
			postBalance := tx.Meta.PostBalances[i]
			if preBalance != postBalance {
				change := int64(postBalance) - int64(preBalance)
				balanceChanges[key.String()] = change
				fmt.Printf("账户: %s\n", key.String())
				fmt.Printf("  余额变化: %.9f SOL\n", float64(change)/1e9)
				fmt.Println()
			}
		}
	}

	// 显示程序调用日志
	fmt.Println("程序调用日志:")
	for _, log := range tx.Meta.LogMessages {
		fmt.Printf("  %s\n", log)
	}

	// 显示转出方和转入方
	fmt.Println("\n转出方:")
	for addr, change := range balanceChanges {
		if change < 0 {
			fmt.Printf("  %s (转出 %.9f SOL)\n", addr, float64(-change)/1e9)
		}
	}

	fmt.Println("\n转入方:")
	if txType == "SOL转账" {
		for addr, change := range balanceChanges {
			if change > 0 && !isSystemAccount(addr) {
				fmt.Printf("  %s (收到 %.9f SOL)\n", addr, float64(change)/1e9)

				// 检查是否是监控的地址
				if isMonitoredAddress(addr, config.Addresses) {
					fmt.Printf("****** OK! 监控地址 %s 收到 %.9f SOL ******\n", addr, float64(change)/1e9)
				}
			}
		}
	} else {
		fmt.Printf("  [%s]\n", txType)
	}

	fmt.Println("------------------------\n")
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
			fmt.Printf("****** 获取区块 %d 失败，%d 秒后重试... (错误: %v) ******\n", blockNum, retryInterval, err)
			time.Sleep(time.Duration(retryInterval) * time.Second)
		}
	}

	if err != nil {
		return fmt.Errorf("获取区块 %d 失败，已重试 %d 次: %v", blockNum, maxRetries, err)
	}

	printBlockInfo(block, blockNum)

	// 处理区块中的交易
	validTxCount := 0
	for i, tx := range block.Transactions {
		// 保存当前交易数量
		prevCount := validTxCount
		processTransaction(i+1, tx, config)
		// 如果交易被处理了（没有被过滤），增加计数
		if validTxCount == prevCount {
			validTxCount++
		}
	}

	if validTxCount == 0 {
		fmt.Printf("****** 区块 %d 中没有符合条件的交易 ******\n", blockNum)
	}

	return nil
}

// 循环监听区块
func monitorBlocks(client *rpc.Client, startBlock uint64, config MonitorConfig) {
	currentBlock := startBlock

	fmt.Printf("****** 开始监听区块，起始区块: %d ******\n", startBlock)
	fmt.Printf("****** 监听间隔: %d 秒 ******\n", monitorInterval)
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
			fmt.Printf("****** 获取最新区块号失败: %v ******\n", err)
			time.Sleep(time.Duration(monitorInterval) * time.Second)
			continue
		}

		// 检查当前区块是否超过最新区块
		if currentBlock > latestSlot {
			fmt.Printf("****** 当前区块 %d 超过最新区块 %d，等待新区块... ******\n", currentBlock, latestSlot)
			time.Sleep(time.Duration(monitorInterval) * time.Second)
			continue
		}

		// 处理当前区块
		fmt.Printf("\n****** 正在处理区块 %d (最新区块: %d) ******\n", currentBlock, latestSlot)
		err = processBlock(client, currentBlock, config)
		if err != nil {
			fmt.Printf("****** 处理区块 %d 失败: %v ******\n", currentBlock, err)
			// 如果处理失败，等待一段时间后继续下一个区块
			time.Sleep(time.Duration(monitorInterval) * time.Second)
		}

		// 移动到下一个区块
		currentBlock++

		// 等待指定间隔
		time.Sleep(time.Duration(monitorInterval) * time.Second)
	}
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
		fmt.Println("******   MONITOR_ADDRESSES=addr1,addr2,addr3  # 监控地址列表（逗号分隔） ******")
		fmt.Println("\n****** 默认只显示SOL转账 ******")
		fmt.Println("\n****** 程序会从指定区块开始，自动循环监听后续区块 ******")
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

	// 开始循环监听
	monitorBlocks(client, startBlock, config)
}

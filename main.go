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

// 从环境变量或命令行参数获取配置
func getConfig() TxTypeConfig {
	config := getDefaultConfig()

	// 从环境变量读取配置
	if os.Getenv("SHOW_TOKEN_TRANSFER") == "true" {
		config.ShowTokenTransfer = true
	}
	if os.Getenv("SHOW_VOTE_TRANSFER") == "true" {
		config.ShowVoteTransfer = true
	}
	if os.Getenv("SHOW_STAKE_TRANSFER") == "true" {
		config.ShowStakeTransfer = true
	}
	if os.Getenv("SHOW_COMPUTE_TRANSFER") == "true" {
		config.ShowComputeTransfer = true
	}
	if os.Getenv("SHOW_OTHER_TRANSFER") == "true" {
		config.ShowOtherTransfer = true
	}

	return config
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

func processTransaction(txIndex int, tx rpc.TransactionWithMeta, config TxTypeConfig) {
	decoded, err := tx.GetTransaction()
	if err != nil {
		return
	}

	// 确定交易类型
	txType := getTxType(tx.Meta.LogMessages)

	// 检查是否应该显示该交易类型
	if !shouldShowTransaction(txType, config) {
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
		MaxSupportedTransactionVersion: &maxVersion, // 添加这个设置
	}

	block, err := client.GetBlockWithOpts(ctx, slot, &opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get block: %v", err)
	}

	return block, nil
}
func printBlockInfo(block *rpc.GetBlockResult, blockNum uint64) {
	fmt.Printf("=== 区块 %d 详细信息 ===\n", blockNum)
	if block.BlockTime != nil {
		fmt.Printf("区块时间: %v\n", time.Unix(int64(*block.BlockTime), 0))
	}
	fmt.Printf("区块高度: %d\n", block.BlockHeight)
	fmt.Printf("父区块: %d\n", block.ParentSlot)
	fmt.Printf("交易数量: %d\n", len(block.Transactions))
	fmt.Println("==================\n")
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: go run main.go <block_number>")
		fmt.Println("\n环境变量配置:")
		fmt.Println("  SHOW_TOKEN_TRANSFER=true    # 显示Token转账")
		fmt.Println("  SHOW_VOTE_TRANSFER=true     # 显示投票交易")
		fmt.Println("  SHOW_STAKE_TRANSFER=true    # 显示质押交易")
		fmt.Println("  SHOW_COMPUTE_TRANSFER=true  # 显示计算预算交易")
		fmt.Println("  SHOW_OTHER_TRANSFER=true    # 显示其他交易")
		fmt.Println("\n默认只显示SOL转账")
		os.Exit(1)
	}

	blockNum, err := strconv.ParseUint(os.Args[1], 10, 64)
	if err != nil {
		fmt.Printf("Error parsing block number: %v\n", err)
		os.Exit(1)
	}

	// 获取配置
	config := getConfig()

	client := rpc.New(rpcEndpoint)

	block, err := getBlockDetails(client, blockNum)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	printBlockInfo(block, blockNum)

	for i, tx := range block.Transactions {
		processTransaction(i+1, tx, config)
	}
}

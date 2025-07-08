package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strconv"
	"time"
)

/**题目#1
实践 POW， 编写程序（编程语言不限）用自己的昵称 + nonce，不断修改nonce 进行 sha256 Hash 运算：

直到满足 4 个 0 开头的哈希值，打印出花费的时间、Hash 的内容及Hash值。
再次运算直到满足 5 个 0 开头的哈希值，打印出花费的时间、Hash 的内容及Hash值。
提交程序你的 Github 链接*/

func main() {
	name := "rambo"
	begin := time.Now().UnixMilli()
	for {
		nonce := rand.Int()
		data := []byte(name + strconv.Itoa(nonce))
		hash := sha256.Sum256(data)
		var shastr1 = hex.EncodeToString(hash[:])
		if shastr1[0:4] == "0000" {
			fmt.Println(shastr1)
			fmt.Println(name + strconv.Itoa(nonce))
			end := time.Now().UnixMilli()
			fmt.Printf("0000 time cost, %d ms \n", end-begin)
			break
		}
	}

	begin = time.Now().UnixMilli()
	for {
		nonce := rand.Int()
		data := []byte(name + strconv.Itoa(nonce))
		hash := sha256.Sum256(data)
		var shastr1 = hex.EncodeToString(hash[:])
		if shastr1[0:5] == "00000" {
			fmt.Println(shastr1)
			fmt.Println(name + strconv.Itoa(nonce))
			end := time.Now().UnixMilli()
			fmt.Printf("00000 time cost, %d ms \n", end-begin)
			break
		}
	}

}
